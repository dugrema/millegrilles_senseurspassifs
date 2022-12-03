use std::collections::{BTreeMap, HashMap, HashSet};
use std::error::Error;
use std::sync::Arc;

use log::{debug, error, warn};
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::bson::{DateTime, doc, Document};
use millegrilles_common_rust::certificats::{calculer_fingerprint, charger_certificat, ValidateurX509, VerificateurPermissions};
// use millegrilles_common_rust::chiffrage_cle::CommandeSauvegarderCle;
use millegrilles_common_rust::{chrono, chrono::Utc};
use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::domaines::GestionnaireDomaine;
use millegrilles_common_rust::formatteur_messages::{DateEpochSeconds, MessageMilleGrille};
use millegrilles_common_rust::generateur_messages::{GenerateurMessages, RoutageMessageAction};
use millegrilles_common_rust::hachages::hacher_uuid;
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::middleware::{Middleware, sauvegarder_traiter_transaction};
use millegrilles_common_rust::mongodb::options::{CountOptions, FindOneAndUpdateOptions, FindOneOptions, FindOptions, Hint, ReturnDocument, UpdateOptions};
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange, QueueType};
use millegrilles_common_rust::recepteur_messages::{MessageValideAction, TypeMessage};
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::serde_json::{json, Value};
use millegrilles_common_rust::tokio::time::{Duration, sleep};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::transactions::{TraiterTransaction, Transaction, TransactionImpl};
use millegrilles_common_rust::verificateur::VerificateurMessage;
use millegrilles_common_rust::mongo_dao::{convertir_bson_deserializable, ChampIndex, IndexOptions, MongoDao, convertir_to_bson, convertir_bson_value, filtrer_doc_id};

pub const DOMAINE_NOM: &str = "SenseursPassifs";
pub const ROLE_RELAI_NOM: &str = "senseurspassifs_relai";

const REQUETE_LISTE_NOEUDS: &str = "listeNoeuds";
const REQUETE_GET_NOEUD: &str = "getNoeud";
const REQUETE_LISTE_SENSEURS_PAR_UUID: &str = "listeSenseursParUuid";
const REQUETE_LISTE_SENSEURS_NOEUD: &str = "listeSenseursPourNoeud";

const EVENEMENT_LECTURE: &str = "lecture";
const EVENEMENT_LECTURE_CONFIRMEE: &str = "lectureConfirmee";

const COMMANDE_INSCRIRE_APPAREIL: &str = "inscrireAppareil";
const COMMANDE_CHALLENGE_APPAREIL: &str = "challengeAppareil";
const COMMANDE_SIGNER_APPAREIL: &str = "signerAppareil";

const TRANSACTION_LECTURE: &str = "lecture";
const TRANSACTION_MAJ_SENSEUR: &str = "majSenseur";
const TRANSACTION_MAJ_NOEUD: &str = "majNoeud";
const TRANSACTION_SUPPRESSION_SENSEUR: &str = "suppressionSenseur";

const INDEX_LECTURES_NOEUD: &str = "lectures_noeud";
const INDEX_LECTURES_SENSEURS: &str = "lectures_senseur";

//const CHAMP_INSTANCE_ID: &str = "instance_id";
const CHAMP_INSTANCE_ID: &str = "instance_id";
const CHAMP_UUID_SENSEUR: &str = "uuid_senseur";
const CHAMP_SENSEURS: &str = "senseurs";

const COLLECTIONS_NOM: &str = "SenseursPassifs";
const COLLECTIONS_INSTANCES: &str = "SenseursPassifs/instances";
const COLLECTIONS_LECTURES: &str = "SenseursPassifs/lectures";
const COLLECTIONS_APPAREILS: &str = "SenseursPassifs/appareils";

#[derive(Clone, Debug)]
pub struct GestionnaireSenseursPassifs {
    pub instance_id: String,
}

#[async_trait]
impl TraiterTransaction for GestionnaireSenseursPassifs {
    async fn appliquer_transaction<M>(&self, middleware: &M, transaction: TransactionImpl) -> Result<Option<MessageMilleGrille>, String>
        where M: ValidateurX509 + GenerateurMessages + MongoDao
    {
        aiguillage_transaction(middleware, transaction, &self).await
    }
}

#[async_trait]
impl GestionnaireDomaine for GestionnaireSenseursPassifs {
    fn get_nom_domaine(&self) -> String { String::from(DOMAINE_NOM) }

    fn get_collection_transactions(&self) -> Option<String> {
        Some(COLLECTIONS_NOM.to_string())
    }

    fn get_collections_documents(&self) -> Vec<String> { vec![
        COLLECTIONS_INSTANCES.to_string(),
        COLLECTIONS_LECTURES.to_string(),
        COLLECTIONS_APPAREILS.to_string(),
    ] }

    fn get_q_transactions(&self) -> Option<String> {
        Some(format!("{}/transactions", DOMAINE_NOM))
    }

    fn get_q_volatils(&self) -> Option<String> {
        Some(format!("{}/volatils", DOMAINE_NOM))
    }

    fn get_q_triggers(&self) -> Option<String> {
        Some(format!("{}/triggers", DOMAINE_NOM))
    }

    fn preparer_queues(&self) -> Vec<QueueType> { preparer_queues(self) }

    fn chiffrer_backup(&self) -> bool {
        true
    }

    async fn preparer_database<M>(&self, middleware: &M) -> Result<(), String> where M: MongoDao + ConfigMessages {
        preparer_index_mongodb_custom(middleware, &self).await
    }

    async fn consommer_requete<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> where M: Middleware + 'static {
        consommer_requete(middleware, message, &self).await
    }

    async fn consommer_commande<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> where M: Middleware + 'static {
        consommer_commande(middleware, message, &self).await
    }

    async fn consommer_transaction<M>(&self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> where M: Middleware + 'static {
        consommer_transaction(middleware, message, self).await
    }

    async fn consommer_evenement<M>(self: &'static Self, middleware: &M, message: MessageValideAction) -> Result<Option<MessageMilleGrille>, Box<dyn Error>> where M: Middleware + 'static {
        consommer_evenement(middleware, message, self).await
    }

    async fn entretien<M>(self: &'static Self, middleware: Arc<M>) where M: Middleware + 'static {
        entretien(middleware).await
    }

    async fn traiter_cedule<M>(self: &'static Self, middleware: &M, trigger: &MessageCedule) -> Result<(), Box<dyn Error>> where M: Middleware + 'static {
        traiter_cedule(middleware, trigger).await
    }

    async fn aiguillage_transaction<M, T>(&self, middleware: &M, transaction: T) -> Result<Option<MessageMilleGrille>, String> where M: ValidateurX509 + GenerateurMessages + MongoDao, T: Transaction {
        aiguillage_transaction(middleware, transaction, &self).await
    }
}

pub fn preparer_queues(gestionnaire: &GestionnaireSenseursPassifs) -> Vec<QueueType> {
    let mut rk_volatils = Vec::new();

    let instance_id = gestionnaire.instance_id.as_str();
    let securite_prive_prot_sec = vec![Securite::L2Prive, Securite::L3Protege, Securite::L4Secure];
    // let securite_prot_sec = vec![Securite::L3Protege, Securite::L4Secure];
    // let securite_prive_prot = vec![Securite::L2Prive, Securite::L3Protege];

    // RK 2.prive, 3.protege et 4.secure
    let requetes_privees: Vec<&str> = vec![
        REQUETE_LISTE_NOEUDS,
        REQUETE_GET_NOEUD,
        REQUETE_LISTE_SENSEURS_PAR_UUID,
        REQUETE_LISTE_SENSEURS_NOEUD,
    ];
    for req in requetes_privees {
        // for sec in &securite_prive_prot {
            rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}.{}", DOMAINE_NOM, instance_id, req), exchange: Securite::L2Prive});
        // }
    }

    // Requete liste noeuds permet de trouver les noeuds sur toutes les partitions (potentiellement plusieurs reponses)
    //for sec in &securite_prive_prot {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_GET_NOEUD), exchange: Securite::L2Prive});
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("requete.{}.{}", DOMAINE_NOM, REQUETE_LISTE_NOEUDS), exchange: Securite::L2Prive});
    //}

    let evenements: Vec<&str> = vec![
        EVENEMENT_LECTURE,
    ];
    for evnt in evenements {
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("evenement.{}.{}", DOMAINE_NOM, evnt), exchange: Securite::L2Prive });
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("evenement.{}.{}.{}", DOMAINE_NOM, instance_id, evnt), exchange: Securite::L2Prive });
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("evenement.{}.{}", ROLE_RELAI_NOM, evnt), exchange: Securite::L2Prive });
        rk_volatils.push(ConfigRoutingExchange { routing_key: format!("evenement.{}.{}.{}", ROLE_RELAI_NOM, instance_id, evnt), exchange: Securite::L2Prive });
    }

    let commandes_transactions: Vec<&str> = vec![
        // Transactions usager, verifier via commande
        TRANSACTION_LECTURE,
        TRANSACTION_MAJ_SENSEUR,
        TRANSACTION_MAJ_NOEUD,
        TRANSACTION_SUPPRESSION_SENSEUR,
        COMMANDE_INSCRIRE_APPAREIL,
        COMMANDE_CHALLENGE_APPAREIL,
        COMMANDE_SIGNER_APPAREIL,
    ];
    for cmd in commandes_transactions {
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.{}", DOMAINE_NOM, cmd), exchange: Securite::L2Prive});
        rk_volatils.push(ConfigRoutingExchange {routing_key: format!("commande.{}.*.{}", DOMAINE_NOM, cmd), exchange: Securite::L2Prive});
    }

    //for sec in securite_prive_prot {
        rk_volatils.push(ConfigRoutingExchange {
            routing_key: format!("commande.{}.{}.{}", DOMAINE_NOM, gestionnaire.instance_id.as_str(), TRANSACTION_LECTURE).into(),
            exchange: Securite::L2Prive
       });
    //}

    let mut queues = Vec::new();

    // Queue de messages volatils (requete, commande, evenements)
    queues.push(QueueType::ExchangeQueue (
        ConfigQueue {
            nom_queue: gestionnaire.get_q_volatils().expect("get_q_volatils").into(),
            routing_keys: rk_volatils,
            ttl: DEFAULT_Q_TTL.into(),
            durable: false,
            autodelete: false,
        }
    ));

    let mut rk_transactions = Vec::new();

    let transactions_sec = vec![TRANSACTION_LECTURE, TRANSACTION_MAJ_SENSEUR, TRANSACTION_MAJ_NOEUD, TRANSACTION_SUPPRESSION_SENSEUR];
    for trans in &transactions_sec {
        rk_transactions.push(ConfigRoutingExchange {
            routing_key: format!("transaction.{}.{}.{}", DOMAINE_NOM, gestionnaire.instance_id.as_str(), trans).into(),
            exchange: Securite::L4Secure,
        });
    }

    // Queue de transactions
    queues.push(QueueType::ExchangeQueue (
        ConfigQueue {
            nom_queue: gestionnaire.get_q_transactions().expect("get_q_transactions").into(),
            routing_keys: rk_transactions,
            ttl: None,
            durable: false,
            autodelete: false,
        }
    ));

    // Queue de triggers pour Pki
    queues.push(QueueType::Triggers (format!("{}.{}", DOMAINE_NOM, gestionnaire.instance_id), Securite::L3Protege));

    queues
}

/// Creer index MongoDB
pub async fn preparer_index_mongodb_custom<M>(middleware: &M, gestionnaire: &GestionnaireSenseursPassifs) -> Result<(), String>
    where M: MongoDao + ConfigMessages
{
    // Index senseurs
    let options_lectures_noeud = IndexOptions {
        nom_index: Some(String::from(INDEX_LECTURES_NOEUD)),
        unique: false
    };
    let champs_index_lectures_noeud = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_INSTANCE_ID), direction: 1},
    );
    middleware.create_index(
        middleware,
        COLLECTIONS_LECTURES,
        champs_index_lectures_noeud,
        Some(options_lectures_noeud)
    ).await?;

    let options_lectures_senseurs = IndexOptions {
        nom_index: Some(String::from(INDEX_LECTURES_SENSEURS)),
        unique: true
    };
    let champs_index_lectures_senseurs = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_UUID_SENSEUR), direction: 1},
    );
    middleware.create_index(
        middleware,
        COLLECTIONS_LECTURES,
        champs_index_lectures_senseurs,
        Some(options_lectures_senseurs)
    ).await?;

    // Index noeuds
    let options_lectures_noeud = IndexOptions {
        nom_index: Some(String::from(INDEX_LECTURES_NOEUD)),
        unique: true
    };
    let champs_index_lectures_noeud = vec!(
        ChampIndex {nom_champ: String::from(CHAMP_INSTANCE_ID), direction: 1},
    );
    middleware.create_index(
        middleware,
        COLLECTIONS_INSTANCES,
        champs_index_lectures_noeud,
        Some(options_lectures_noeud)
    ).await?;

    Ok(())
}

pub async fn entretien<M>(_middleware: Arc<M>)
    where M: Middleware + 'static
{
    loop {
        sleep(Duration::new(30, 0)).await;
        debug!("Cycle entretien {}", DOMAINE_NOM);
    }
}

pub async fn traiter_cedule<M>(_middleware: &M, _trigger: &MessageCedule) -> Result<(), Box<dyn Error>>
where M: Middleware + 'static {
    // let message = trigger.message;

    debug!("Traiter cedule {}", DOMAINE_NOM);

    Ok(())
}

async fn consommer_requete<M>(middleware: &M, message: MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + VerificateurMessage
{
    debug!("Consommer requete : {:?}", &message.message);

    // Autorisation : On accepte les requetes de 3.protege ou 4.secure
    match message.verifier_exchanges(vec![Securite::L2Prive, Securite::L3Protege, Securite::L4Secure]) {
        true => Ok(()),
        false => {
            match message.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
                true => Ok(()),
                false => Err(format!("senseurspassifs.consommer_requete Autorisation invalide (pas d'un exchange reconnu) : {}", message.routing_key))
            }
        },
    }?;

    match message.domaine.as_str() {
        DOMAINE_NOM => {
            match message.action.as_str() {
                REQUETE_LISTE_NOEUDS => requete_liste_noeuds(middleware, message, gestionnaire).await,
                REQUETE_LISTE_SENSEURS_PAR_UUID => requete_liste_senseurs_par_uuid(middleware, message, gestionnaire).await,
                REQUETE_LISTE_SENSEURS_NOEUD => requete_liste_senseurs_pour_noeud(middleware, message, gestionnaire).await,
                REQUETE_GET_NOEUD => requete_get_noeud(middleware, message, gestionnaire).await,
                _ => {
                    error!("Message requete/action inconnue : '{}'. Message dropped.", message.action);
                    Ok(None)
                },
            }
        },
        _ => {
            error!("Message requete/domaine inconnu : '{}'. Message dropped.", message.domaine);
            Ok(None)
        },
    }
}

async fn consommer_evenement<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("senseurspassifs.consommer_evenement Consommer evenement : {:?}", &m.message);

    // Autorisation : doit etre de niveau 2.prive, 3.protege ou 4.secure
    match m.verifier_exchanges(vec![Securite::L2Prive, Securite::L3Protege, Securite::L4Secure]) {
        true => Ok(()),
        false => Err(format!("senseurspassifs.consommer_evenement: Evenement invalide (pas 3.protege ou 4.secure)")),
    }?;

    match m.action.as_str() {
        EVENEMENT_LECTURE => { evenement_domaine_lecture(middleware, &m, gestionnaire).await?; Ok(None) },
        _ => Err(format!("senseurspassifs.consommer_evenement: Mauvais type d'action pour une transaction : {}", m.action))?,
    }
}

async fn consommer_transaction<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs) -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
where
    M: ValidateurX509 + GenerateurMessages + MongoDao,
{
    debug!("senseurspassifs.consommer_transaction Consommer transaction : {:?}", &m.message);

    // Autorisation : doit etre de niveau 2.prive, 3.protege ou 4.secure
    match m.verifier_exchanges(vec![Securite::L2Prive, Securite::L3Protege, Securite::L4Secure]) {
        true => Ok(()),
        false => {
            match m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
                true => Ok(()),
                false => Err(format!("senseurspassifs.consommer_transaction: Trigger cedule autorisation invalide (pas 4.secure ou proprietaire)"))
            }
        },
    }?;

    match m.action.as_str() {
        TRANSACTION_MAJ_SENSEUR |
        TRANSACTION_MAJ_NOEUD |
        TRANSACTION_LECTURE |
        TRANSACTION_SUPPRESSION_SENSEUR => {
            Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
        },
        _ => Err(format!("senseurspassifs.consommer_transaction: Mauvais type d'action pour une transaction : {}", m.action))?,
    }
}

async fn consommer_commande<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao + VerificateurMessage
{
    debug!("consommer_commande : {:?}", &m.message);

    // Autorisation : doit etre un message via exchange
    match m.verifier_exchanges(vec!(Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure)) {
        true => Ok(()),
        false => {
            // Verifier si on a un certificat delegation globale
            match m.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE) {
                true => Ok(()),
                false => Err(format!("senseurspassifs.consommer_commande: Commande autorisation invalide pour message {:?}", m.correlation_id)),
            }
        }
    }?;

    match m.action.as_str() {
        COMMANDE_INSCRIRE_APPAREIL => commande_inscrire_appareil(middleware, m, gestionnaire).await,
        COMMANDE_CHALLENGE_APPAREIL => commande_challenge_appareil(middleware, m, gestionnaire).await,
        COMMANDE_SIGNER_APPAREIL => commande_signer_appareil(middleware, m, gestionnaire).await,
        TRANSACTION_MAJ_SENSEUR |
        TRANSACTION_MAJ_NOEUD |
        TRANSACTION_SUPPRESSION_SENSEUR => {
            // Pour l'instant, aucune autre validation. On traite comme une transaction
            Ok(sauvegarder_traiter_transaction(middleware, m, gestionnaire).await?)
        },
        _ => Err(format!("senseurspassifs.consommer_commande: Commande {} inconnue : {}, message dropped", DOMAINE_NOM, m.action))?,
    }
}

// async fn commande_sauvegarder_cle<M>(middleware: &M, m: MessageValideAction, gestionnaire_ca: &GestionnaireSenseursPassifs)
//     -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
//     where M: GenerateurMessages + MongoDao,
// {
//     debug!("commande_sauvegarder_cle Consommer commande : {:?}", & m.message);
//     let commande: CommandeSauvegarderCle = m.message.get_msg().map_contenu(None)?;
//     debug!("Commande sauvegarder cle parsed : {:?}", commande);
//
//     let fingerprint = gestionnaire_ca.fingerprint.as_str();
//     let mut doc_bson: Document = commande.clone().into();
//
//     // // Sauvegarder pour partition CA, on retire la partition recue
//     // let _ = doc_bson.remove("partition");
//
//     // Retirer cles, on re-insere la cle necessaire uniquement
//     doc_bson.remove("cles");
//
//     let cle = match commande.cles.get(fingerprint) {
//         Some(cle) => cle.as_str(),
//         None => {
//             let message = format!("maitredescles_ca.commande_sauvegarder_cle: Erreur validation - commande sauvegarder cles ne contient pas la cle CA : {:?}", commande);
//             warn!("{}", message);
//             let reponse_err = json!({"ok": false, "err": message});
//             return Ok(Some(middleware.formatter_reponse(&reponse_err, None)?));
//         }
//     };
//
//     doc_bson.insert("dirty", true);
//     doc_bson.insert("cle", cle);
//     doc_bson.insert(CHAMP_CREATION, Utc::now());
//     doc_bson.insert(CHAMP_MODIFICATION, Utc::now());
//
//     let nb_cles = commande.cles.len();
//     let non_dechiffrable = nb_cles < 2;
//     debug!("commande_sauvegarder_cle: On a recu {} cles, non-dechiffables (presume) : {}", nb_cles, non_dechiffrable);
//     doc_bson.insert("non_dechiffrable", non_dechiffrable);
//
//     let ops = doc! { "$setOnInsert": doc_bson };
//
//     debug!("commande_sauvegarder_cle: Ops bson : {:?}", ops);
//
//     let filtre = doc! { "hachage_bytes": commande.hachage_bytes.as_str() };
//     let opts = UpdateOptions::builder().upsert(true).build();
//
//     let collection = middleware.get_collection(NOM_COLLECTION_CLES)?;
//     let resultat = collection.update_one(filtre, ops, opts).await?;
//     debug!("commande_sauvegarder_cle Resultat update : {:?}", resultat);
//
//     if let Some(uid) = resultat.upserted_id {
//         debug!("commande_sauvegarder_cle Nouvelle cle insere _id: {}, generer transaction", uid);
//         let transaction = TransactionCle::new_from_commande(&commande, fingerprint)?;
//         let routage = RoutageMessageAction::builder(DOMAINE_NOM, TRANSACTION_CLE)
//             .exchanges(vec![Securite::L4Secure])
//             .build();
//         middleware.soumettre_transaction(routage, &transaction, false).await?;
//     }
//
//     Ok(middleware.reponse_ok()?)
// }

async fn aiguillage_transaction<M, T>(middleware: &M, transaction: T, gestionnaire: &GestionnaireSenseursPassifs) -> Result<Option<MessageMilleGrille>, String>
    where
        M: ValidateurX509 + GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("aiguillage_transaction {}", transaction.get_action());
    match transaction.get_action() {
        TRANSACTION_MAJ_SENSEUR => transaction_maj_senseur(middleware, transaction, gestionnaire).await,
        TRANSACTION_MAJ_NOEUD => transaction_maj_noeud(middleware, transaction, gestionnaire).await,
        TRANSACTION_SUPPRESSION_SENSEUR => transaction_suppression_senseur(middleware, transaction, gestionnaire).await,
        TRANSACTION_LECTURE => transaction_lectures(middleware, transaction, gestionnaire).await,
        _ => Err(format!("senseurspassifs.aiguillage_transaction: Transaction {} est de type non gere : {}", transaction.get_uuid_transaction(), transaction.get_action())),
    }
}

async fn transaction_maj_senseur<M, T>(middleware: &M, transaction: T, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_maj_senseur Consommer transaction : {:?}", &transaction);
    let transaction_cle = match transaction.clone().convertir::<TransactionMajSenseur>() {
        Ok(t) => t,
        Err(e) => Err(format!("senseurspassifs.transaction_maj_senseur Erreur conversion transaction : {:?}", e))?
    };
    debug!("transaction_maj_senseur Transaction lue {:?}", transaction_cle);
    let collection = middleware.get_collection(COLLECTIONS_LECTURES)?;

    let document_transaction = {
        let mut set_ops = doc! {CHAMP_INSTANCE_ID: &transaction_cle.instance_id};

        let mut valeur_transactions = match convertir_to_bson(transaction_cle.clone()) {
            Ok(v) => v,
            Err(e) => Err(format!("senseurspassifs.transaction_maj_senseur Erreur conversion transaction en bson : {:?}", e))?
        };
        filtrer_doc_id(&mut valeur_transactions);
        valeur_transactions.remove("uuid_senseur");
        set_ops.extend(valeur_transactions);

        let ops = doc! {
            "$set": set_ops,
            "$setOnInsert": {
                CHAMP_CREATION: Utc::now(),
                CHAMP_UUID_SENSEUR: &transaction_cle.uuid_senseur,
            },
            "$currentDate": {CHAMP_MODIFICATION: true}
        };
        let filtre = doc! { CHAMP_UUID_SENSEUR: &transaction_cle.uuid_senseur };
        let opts = FindOneAndUpdateOptions::builder().upsert(true).return_document(ReturnDocument::After).build();
        match collection.find_one_and_update(filtre, ops, Some(opts)).await {
            Ok(r) => match r {
                Some(r) => match convertir_bson_deserializable::<TransactionMajSenseur>(r) {
                    Ok(r) => r,
                    Err(e) => Err(format!("senseurspassifs.transaction_maj_senseur Erreur conversion document senseur en doc TransactionMajSenseur: {:?}", e))?
                },
                None => Err(format!("senseurspassifs.transaction_maj_senseur Erreur chargement doc senseur apres MAJ"))?
            },
            Err(e) => Err(format!("senseurspassifs.transaction_maj_senseur Erreur traitement transaction senseur : {:?}", e))?
        }
    };
    debug!("transaction_maj_senseur Resultat maj transaction : {:?}", document_transaction);

    // Maj noeud
    {
        let filtre = doc! { CHAMP_INSTANCE_ID: &transaction_cle.instance_id };
        let ops = doc! {
            "$setOnInsert": {
                CHAMP_CREATION: Utc::now(),
                CHAMP_INSTANCE_ID: &transaction_cle.instance_id,
            },
            "$currentDate": {CHAMP_MODIFICATION: true}
        };
        let opts = UpdateOptions::builder().upsert(true).build();
        let collection_noeud = match middleware.get_collection(COLLECTIONS_INSTANCES) {
            Ok(n) => n,
            Err(e) => Err(format!("senseurspassifs.transaction_maj_senseur Erreur ouverture collection noeuds: {:?}", e))?
        };
        let resultat = match collection_noeud.update_one(filtre, ops, Some(opts)).await {
            Ok(r) => r,
            Err(e) => Err(format!("senseurspassifs.transaction_maj_senseur Erreur traitement maj noeud : {:?}", e))?
        };

        if let Some(_) = resultat.upserted_id {
            debug!("transaction_maj_senseur Creer transaction pour instance_id {}", transaction_cle.instance_id);
            let transaction = TransactionMajNoeud::new(&transaction_cle.instance_id);
            let routage = RoutageMessageAction::builder(DOMAINE_NOM, TRANSACTION_MAJ_NOEUD)
                .exchanges(vec![Securite::L4Secure])
                .partition(&gestionnaire.instance_id)
                .build();
            middleware.soumettre_transaction(routage, &transaction, false).await?;
        }
    }

    {
        let routage_evenement = RoutageMessageAction::builder(DOMAINE_NOM, TRANSACTION_MAJ_SENSEUR)
            .exchanges(vec![Securite::L2Prive])
            .partition(&document_transaction.instance_id)
            .build();
        middleware.emettre_evenement(routage_evenement, &document_transaction).await?;
    }

    debug!("transaction_maj_senseur Resultat ajout transaction : {:?}", document_transaction);
    let reponse = match middleware.formatter_reponse(&document_transaction, None) {
        Ok(reponse) => Ok(Some(reponse)),
        Err(e) => Err(format!("senseurspassifs.document_transaction Erreur preparation reponse : {:?}", e))
    }?;

    Ok(reponse)
}

async fn transaction_maj_noeud<M, T>(middleware: &M, transaction: T, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_maj_noeud Consommer transaction : {:?}", &transaction);
    let contenu_transaction = match transaction.clone().convertir::<TransactionMajNoeud>() {
        Ok(t) => t,
        Err(e) => Err(format!("senseurspassifs.transaction_maj_noeud Erreur conversion transaction : {:?}", e))?
    };
    debug!("transaction_maj_noeud Transaction lue {:?}", contenu_transaction);

    let document_transaction = {
        let mut valeurs = match convertir_to_bson(contenu_transaction.clone()) {
            Ok(v) => v,
            Err(e) => Err(format!("senseurspassifs.transaction_maj_noeud Erreur conversion transaction a bson : {:?}", e))?
        };
        valeurs.remove("instance_id"); // Enlever cle

        let mut ops = doc! {
            "$setOnInsert": {
                CHAMP_CREATION: Utc::now(),
                CHAMP_INSTANCE_ID: &contenu_transaction.instance_id,
            },
            "$currentDate": {CHAMP_MODIFICATION: true}
        };

        if valeurs.len() > 0 {
            ops.insert("$set", valeurs);
        }

        let filtre = doc! { CHAMP_INSTANCE_ID: &contenu_transaction.instance_id };
        let collection = middleware.get_collection(COLLECTIONS_INSTANCES)?;
        let opts = FindOneAndUpdateOptions::builder().upsert(true).return_document(ReturnDocument::After).build();
        match collection.find_one_and_update(filtre, ops, Some(opts)).await {
            Ok(r) => {
                match r {
                    Some(r) => {
                        debug!("Conversion document maj recu : {:?}", r);
                        match convertir_bson_deserializable::<TransactionMajNoeud>(r) {
                            Ok(r) => r,
                            Err(e) => Err(format!("senseurspassifs.transaction_maj_noeud Erreur conversion a TransactionMajNoeud : {:?}", e))?
                        }
                    },
                    None => Err(format!("senseurspassifs.transaction_maj_noeud Erreur recuperation document transaction maj"))?
                }
            },
            Err(e) => Err(format!("senseurspassifs.transaction_maj_noeud Erreur traitement transaction senseur : {:?}", e))?
        }
    };

    {
        let routage_evenement = RoutageMessageAction::builder(DOMAINE_NOM, TRANSACTION_MAJ_NOEUD)
            .exchanges(vec![Securite::L2Prive])
            .partition(&document_transaction.instance_id)
            .build();
        middleware.emettre_evenement(routage_evenement, &document_transaction).await?;
    }

    debug!("transaction_maj_noeud Resultat ajout transaction : {:?}", document_transaction);
    match middleware.formatter_reponse(&document_transaction, None) {
        Ok(reponse) => Ok(Some(reponse)),
        Err(e) => Err(format!("senseurspassifs.transaction_maj_noeud Erreur preparation reponse : {:?}", e))
    }
}

async fn transaction_suppression_senseur<M, T>(middleware: &M, transaction: T, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_suppression_senseur Consommer transaction : {:?}", &transaction);
    let contenu_transaction = match transaction.clone().convertir::<TransactionSupprimerSenseur>() {
        Ok(t) => t,
        Err(e) => Err(format!("senseurspassifs.transaction_suppression_senseur Erreur conversion transaction : {:?}", e))?
    };
    debug!("transaction_suppression_senseur Transaction lue {:?}", contenu_transaction);

    {
        let filtre = doc! { CHAMP_UUID_SENSEUR: &contenu_transaction.uuid_senseur };
        let collection = middleware.get_collection(COLLECTIONS_LECTURES)?;
        let resultat = match collection.delete_one(filtre, None).await {
            Ok(r) => r,
            Err(e) => Err(format!("senseurspassifs.transaction_suppression_senseur Erreur traitement transaction senseur : {:?}", e))?
        };
        debug!("transaction_suppression_senseur Resultat suppression senseur : {:?}", resultat);
    }

    middleware.reponse_ok()
}

async fn transaction_lectures<M, T>(middleware: &M, transaction: T, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, String>
    where
        M: GenerateurMessages + MongoDao,
        T: Transaction
{
    debug!("transaction_lectures Consommer transaction : {:?}", &transaction);
    let contenu_transaction = match transaction.clone().convertir::<TransactionLectures>() {
        Ok(t) => t,
        Err(e) => Err(format!("senseurspassifs.transaction_lectures Erreur conversion transaction : {:?}", e))?
    };
    debug!("transaction_lectures Transaction lue {:?}", contenu_transaction);

    // Trouver la plus recente lecture
    match contenu_transaction.plus_recente_lecture() {
        Some(plus_recente_lecture) => {

            let senseur = doc! {
                "valeur": &plus_recente_lecture.valeur,
                "timestamp": &plus_recente_lecture.timestamp,
                "type": &contenu_transaction.type_,
            };

            let filtre = doc! {
                CHAMP_UUID_SENSEUR: &contenu_transaction.uuid_senseur,
                "derniere_lecture": &plus_recente_lecture.timestamp,
            };
            let filtre = doc! { CHAMP_UUID_SENSEUR: &contenu_transaction.uuid_senseur };
            let collection = middleware.get_collection(COLLECTIONS_LECTURES)?;
            let ops = doc! {
                "$set": {
                    format!("{}.{}", CHAMP_SENSEURS, &contenu_transaction.senseur): senseur,
                    "derniere_lecture": &plus_recente_lecture.timestamp,
                    "derniere_lecture_dt": &plus_recente_lecture.timestamp.get_datetime(),
                },
                "$setOnInsert": {
                    CHAMP_CREATION: Utc::now(),
                    CHAMP_INSTANCE_ID: &contenu_transaction.instance_id,
                    CHAMP_UUID_SENSEUR: &contenu_transaction.uuid_senseur,
                },
                "$currentDate": { CHAMP_MODIFICATION: true },
            };
            let opts = UpdateOptions::builder().upsert(true).build();
            let resultat = match collection.update_one(filtre, ops, Some(opts)).await {
                Ok(r) => r,
                Err(e) => Err(format!("senseurspassifs.transaction_lectures Erreur traitement transaction senseur : {:?}", e))?
            };
            debug!("transaction_lectures Resultat : {:?}", resultat);

            if let Some(_) = resultat.upserted_id {
                debug!("Creer transaction pour nouveau senseur {}", contenu_transaction.uuid_senseur);
                let transaction = TransactionMajSenseur::new(
                    &contenu_transaction.uuid_senseur, &contenu_transaction.instance_id);
                let routage = RoutageMessageAction::builder(DOMAINE_NOM, TRANSACTION_MAJ_SENSEUR)
                    .exchanges(vec![Securite::L4Secure])
                    .partition(&gestionnaire.instance_id)
                    .build();
                middleware.soumettre_transaction(routage, &transaction, false).await?;
            }
        },
        None => {
            warn!("Transaction lectures senseur {} recue sans contenu (aucunes lectures)", contenu_transaction.uuid_senseur);
        }
    }

    middleware.reponse_ok()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TransactionSupprimerSenseur {
    uuid_senseur: String
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TransactionLectures {
    /// Identificateur unique de l'appareil
    uuid_senseur: String,

    /// Identificateur interne du senseur sur l'appareil
    senseur: String,

    /// UUID du noeud MilleGrille
    instance_id: String,

    /// Type de lecture, e.g. temperature, humidite, pression, voltage, batterie, etc.
    #[serde(rename="type")]
    type_: String,

    /// Heure de base des lectures dans la transaction en epoch secs
    timestamp: DateEpochSeconds,

    /// Moyenne des lectures
    avg: f64,

    /// Valeur max des lectures
    max: f64,

    /// Valeur min des lectures
    min: f64,

    /// Plus vieille date de lecture
    timestamp_min: DateEpochSeconds,

    /// Plus recente date de lecture
    timestamp_max: DateEpochSeconds,

    /// Liste des lectures
    lectures: Vec<LectureTransaction>
}

impl TransactionLectures {
    fn plus_recente_lecture(&self) -> Option<LectureTransaction> {
        let mut date_lecture: &chrono::DateTime<Utc> = &chrono::MIN_DATETIME;
        let mut lecture = None;
        for l in &self.lectures {
            if date_lecture < l.timestamp.get_datetime() {
                lecture = Some(l);
                date_lecture = l.timestamp.get_datetime();
            }
        }
        match lecture {
            Some(l) => Some(l.to_owned()),
            None => None
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LectureTransaction {
    timestamp: DateEpochSeconds,
    valeur: f64,
}

async fn requete_liste_noeuds<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_liste_noeuds Consommer requete : {:?}", & m.message);

    let noeuds = {
        let filtre = doc! { };
        let projection = doc! {
            CHAMP_INSTANCE_ID: 1,
            "securite": 1,
            CHAMP_MODIFICATION: 1,
            "descriptif": 1,
            "lcd_actif": 1, "lcd_vpin_onoff": 1, "lcd_vpin_navigation": 1, "lcd_affichage": 1,
        };
        let opts = FindOptions::builder().projection(projection).build();
        let collection = middleware.get_collection(COLLECTIONS_INSTANCES)?;
        let mut curseur = collection.find(filtre, opts).await?;

        let mut noeuds = Vec::new();
        while let Some(d) = curseur.next().await {
            let noeud: TransactionMajNoeud = convertir_bson_deserializable(d?)?;
            noeuds.push(noeud);
        }

        noeuds
    };

    let reponse = json!({ "ok": true, "noeuds": noeuds, "partition": &gestionnaire.instance_id });
    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

async fn requete_liste_senseurs_par_uuid<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_liste_senseurs_par_uuid Consommer requete : {:?}", & m.message);
    let requete: RequeteSenseursParUuid = m.message.get_msg().map_contenu(None)?;

    let senseurs = {
        let filtre = doc! { CHAMP_UUID_SENSEUR: {"$in": &requete.uuid_senseurs} };
        let projection = doc! {
            CHAMP_UUID_SENSEUR: 1,
            CHAMP_INSTANCE_ID: 1,
            // CHAMP_MODIFICATION: 1,
            "derniere_lecture": 1,
            CHAMP_SENSEURS: 1,
            "securite": 1,
            "descriptif": 1,
        };
        let opts = FindOptions::builder().projection(projection).build();
        let collection = middleware.get_collection(COLLECTIONS_LECTURES)?;
        let mut curseur = collection.find(filtre, opts).await?;

        let mut senseurs = Vec::new();
        while let Some(d) = curseur.next().await {
            let mut noeud: InformationSenseur = convertir_bson_deserializable(d?)?;
            senseurs.push(noeud);
        }

        senseurs
    };

    let reponse = json!({ "ok": true, "senseurs": senseurs, "partition": &gestionnaire.instance_id });
    let reponse_formattee = middleware.formatter_reponse(&reponse, None)?;
    debug!("Reponse formattee : {:?}", reponse_formattee);
    Ok(Some(reponse_formattee))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteSenseursParUuid {
    uuid_senseurs: Vec<String>,
}

async fn requete_liste_senseurs_pour_noeud<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_liste_senseurs_pour_noeud Consommer requete : {:?}", & m.message);
    let requete: RequeteSenseursPourNoeud = m.message.get_msg().map_contenu(None)?;

    let senseurs = {
        let filtre = doc! { CHAMP_INSTANCE_ID: &requete.instance_id };
        let projection = doc! {
            CHAMP_UUID_SENSEUR: 1,
            CHAMP_INSTANCE_ID: 1,
            "derniere_lecture": 1,
            CHAMP_SENSEURS: 1,
            "securite": 1,
            "descriptif": 1,
        };
        let opts = FindOptions::builder().projection(projection).build();
        let collection = middleware.get_collection(COLLECTIONS_LECTURES)?;
        let mut curseur = collection.find(filtre, opts).await?;

        let mut senseurs = Vec::new();
        while let Some(d) = curseur.next().await {
            debug!("Document senseur bson : {:?}", d);
            let mut noeud: InformationSenseur = convertir_bson_deserializable(d?)?;
            senseurs.push(noeud);
        }

        senseurs
    };

    let reponse = json!({ "ok": true, "senseurs": senseurs, "partition": &gestionnaire.instance_id });
    let reponse_formattee = middleware.formatter_reponse(&reponse, None)?;
    debug!("Reponse formattee : {:?}", reponse_formattee);
    Ok(Some(reponse_formattee))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteSenseursPourNoeud {
    instance_id: String,
}

async fn requete_get_noeud<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("requete_get_noeud Consommer requete : {:?}", & m.message);
    let requete: RequeteGetNoeud = m.message.get_msg().map_contenu(None)?;

    let noeud = {
        let filtre = doc! { };
        let projection = doc! {
            CHAMP_INSTANCE_ID: 1,
            "securite": 1,
            CHAMP_MODIFICATION: 1,
            "descriptif": 1,
            "lcd_actif": 1, "lcd_affichage": 1,
        };
        let filtre = doc! { CHAMP_INSTANCE_ID: &requete.instance_id };
        let opts = FindOneOptions::builder().projection(projection).build();
        let collection = middleware.get_collection(COLLECTIONS_INSTANCES)?;
        let mut doc = collection.find_one(filtre, opts).await?;

        match doc {
            Some(mut n) => {
                filtrer_doc_id(&mut n);
                Some(convertir_bson_value(n)?)
            },
            None => None
        }
    };

    let reponse = match noeud {
        Some(mut val_noeud) => {
            // Inserer valeurs manquantes pour la response
            if let Some(mut o) = val_noeud.as_object_mut() {
                o.insert("ok".into(), Value::Bool(true));
                o.insert("partition".into(), Value::String(gestionnaire.instance_id.clone()));
            }
            val_noeud
        },
        None => {
            // Confirmer que la requete s'est bien executee mais rien trouve
            json!({ "ok": true, "partition": &gestionnaire.instance_id, CHAMP_INSTANCE_ID: None::<&str>})
        }
    };

    debug!("requete_get_noeud Reponse : {:?}", reponse);

    Ok(Some(middleware.formatter_reponse(&reponse, None)?))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequeteGetNoeud {
    instance_id: String
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InformationSenseur {
    derniere_lecture: Option<DateEpochSeconds>,
    descriptif: Option<String>,
    instance_id: String,
    securite: Option<String>,

    senseurs: Option<BTreeMap<String, LectureSenseur>>,
    uuid_senseur: String,
}

async fn evenement_domaine_lecture<M>(middleware: &M, m: &MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs) -> Result<(), Box<dyn Error>>
    where M: ValidateurX509 + GenerateurMessages + MongoDao
{
    debug!("evenement_domaine_lecture Recu evenement {:?}", &m.message);
    let mut lecture: EvenementLecture = m.message.get_msg().map_contenu(None)?;
    debug!("Evenement mappe : {:?}", lecture);

    // Trouver date de la plus recente lecture
    lecture.calculer_derniere_lecture();

    let mut filtre = doc! { CHAMP_UUID_SENSEUR: &lecture.uuid_senseur };

    // Convertir date en format DateTime pour conserver, ajouter filtre pour eviter de
    // mettre a jour un senseur avec informations plus vieilles
    let derniere_lecture_dt = match lecture.derniere_lecture.as_ref()  {
        Some(l) => {
            filtre.insert("derniere_lecture", doc! {"$lt": l.get_datetime().timestamp()});
            Some(l.get_datetime())
        },
        None => None
    };

    let mut set_ops = doc! {
        "derniere_lecture": &lecture.derniere_lecture,
        "derniere_lecture_dt": derniere_lecture_dt,
    };

    // let senseurs = convertir_to_bson(&lecture.senseurs)?;
    for (senseur_id, lecture_senseur) in &lecture.senseurs {
        set_ops.insert(format!("senseurs.{}", senseur_id), convertir_to_bson(&lecture_senseur)?);
    }

    let ops = doc! {
        "$set": set_ops,
        // {
        //     CHAMP_SENSEURS: senseurs,
        //     "derniere_lecture": &lecture.derniere_lecture,
        //     "derniere_lecture_dt": derniere_lecture_dt,
        // },
        "$setOnInsert": {
            CHAMP_CREATION: Utc::now(),
            CHAMP_INSTANCE_ID: &lecture.instance_id,
            CHAMP_UUID_SENSEUR: &lecture.uuid_senseur,
        },
        "$currentDate": { CHAMP_MODIFICATION: true },
    };
    let collection = middleware.get_collection(COLLECTIONS_LECTURES)?;
    let opts = UpdateOptions::builder().upsert(true).build();
    let resultat_update = collection.update_one(filtre, ops, Some(opts)).await?;
    debug!("evenement_domaine_lecture Resultat update : {:?}", resultat_update);

    // Si on a cree un nouvel element, creer le senseur (et potentiellement le noeud)
    if let Some(uid) = resultat_update.upserted_id {
        debug!("Creation nouvelle transaction pour senseur {}", lecture.uuid_senseur);
        let transaction = TransactionMajSenseur::new(&lecture.uuid_senseur, &lecture.instance_id);
        let routage = RoutageMessageAction::builder(DOMAINE_NOM, TRANSACTION_MAJ_SENSEUR)
            .exchanges(vec![Securite::L4Secure])
            .partition(&gestionnaire.instance_id)
            .build();
        middleware.soumettre_transaction(routage, &transaction, false).await?;
    }

    // Charger etat a partir de mongo - va recuperer dates, lectures d'autres apps
    let info_senseur = {
        let projection = doc! {
            CHAMP_UUID_SENSEUR: 1,
            CHAMP_INSTANCE_ID: 1,
            "derniere_lecture": 1,
            CHAMP_SENSEURS: 1,
            "securite": 1,
            "descriptif": 1,
        };
        let filtre = doc! { CHAMP_UUID_SENSEUR: &lecture.uuid_senseur };
        let opts = FindOneOptions::builder().projection(projection).build();
        let collection = middleware.get_collection(COLLECTIONS_LECTURES)?;
        let doc_senseur = collection.find_one(filtre, opts).await?;

        match doc_senseur {
            Some(d) => {
                let info_senseur: InformationSenseur = convertir_bson_deserializable(d)?;
                debug!("Chargement info senseur pour evenement confirmation : {:?}", info_senseur);
                info_senseur
            },
            None => Err(format!("Erreur chargement senseur a partir de mongo, aucun match sur {}", &lecture.uuid_senseur))?
        }
    };

    // Bouncer l'evenement sur tous les exchanges appropries
    let routage = RoutageMessageAction::builder(DOMAINE_NOM, EVENEMENT_LECTURE_CONFIRMEE)
        .exchanges(vec![Securite::L2Prive, Securite::L3Protege, Securite::L4Secure])
        .build();

    match middleware.emettre_evenement(routage, &info_senseur).await {
        Ok(_) => (),
        Err(e) => warn!("senseurspassifs.evenement_domaine_lecture Erreur emission evenement lecture confirmee : {:?}", e)
    }

    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EvenementLecture {
    instance_id: String,
    uuid_senseur: String,
    senseurs: HashMap<String, LectureSenseur>,
    derniere_lecture: Option<DateEpochSeconds>,
}

impl EvenementLecture {
    fn calculer_derniere_lecture(&mut self) {
        let mut date_lecture: &chrono::DateTime<Utc> = &chrono::MIN_DATETIME;
        for l in self.senseurs.values() {
            date_lecture = &l.timestamp.get_datetime().max(date_lecture);
        }

        match date_lecture == &chrono::MIN_DATETIME {
            true => {
                self.derniere_lecture = None
            },
            false => {
                self.derniere_lecture = Some(DateEpochSeconds::from(date_lecture.to_owned()));
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LectureSenseur {
    timestamp: DateEpochSeconds,
    #[serde(rename="type")]
    type_: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    valeur: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    valeur_str: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TransactionMajSenseur {
    uuid_senseur: String,
    instance_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    descriptif: Option<String>,
}

impl TransactionMajSenseur {
    pub fn new<S, T>(uuid_senseur: S, uuid_noeud: T)  -> Self
        where S: Into<String>, T: Into<String>
    {
        TransactionMajSenseur {
            uuid_senseur: uuid_senseur.into(),
            instance_id: uuid_noeud.into(),
            descriptif: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TransactionMajNoeud {
    instance_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    descriptif: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    securite: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lcd_actif: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lcd_affichage: Option<Vec<LigneAffichageLcd>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LigneAffichageLcd {
    uuid: String,
    appareil: String,
    affichage: String,
}

impl TransactionMajNoeud {
    pub fn new<S>(uuid_noeud: S)  -> Self
        where S: Into<String>
    {
        TransactionMajNoeud {
            instance_id: uuid_noeud.into(),
            descriptif: None,
            securite: None,
            lcd_actif: None,
            lcd_affichage: None,
        }
    }
}

async fn commande_inscrire_appareil<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("commande_inscrire_appareil Consommer requete : {:?}", & m.message);
    let mut commande: CommandeInscrireAppareil = m.message.get_msg().map_contenu(None)?;
    debug!("commande_inscrire_appareil Commande mappee : {:?}", commande);

    let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;
    let filtre_appareil = doc! {
        "uuid_appareil": &commande.uuid_appareil,
        "user_id": &commande.user_id,
    };

    let doc_appareil_option = {
        let set_on_insert = doc! {
            CHAMP_CREATION: Utc::now(),
            CHAMP_MODIFICATION: Utc::now(),
            "uuid_appareil": &commande.uuid_appareil,
            "cle_publique": &commande.cle_publique,
            "csr": &commande.csr,
            "instance_id": &commande.instance_id,
            "user_id": &commande.user_id,
            "challenge_complete": false,
        };
        let options = FindOneAndUpdateOptions::builder()
            .upsert(true)
            .return_document(ReturnDocument::After)
            .build();
        let ops = doc! { "$setOnInsert": set_on_insert };
        collection.find_one_and_update(filtre_appareil.clone(), ops, Some(options)).await?
    };

    if let Some(d) = doc_appareil_option {
        let doc_appareil: DocAppareil = convertir_bson_deserializable(d)?;
        let mut certificat = doc_appareil.certificat;


        match certificat {
            Some(c) => {
                let mut repondre_certificat = false;

                // Comparer cles publiques - si differentes, on genere un nouveau certificat
                if let Some(cle_publique_db) = doc_appareil.cle_publique.as_ref() {
                    if &commande.cle_publique != cle_publique_db {
                        debug!("commande_inscrire_appareil Reset certificat, demande avec nouveau CSR");
                        certificat = None;
                        let ops = doc! {
                            "$set": {
                                "cle_publique": &commande.cle_publique,
                                "csr": &commande.csr,
                            },
                            "$unset": {"certificat": true, "fingerprint": true},
                            "$currentDate": {CHAMP_MODIFICATION: true},
                        };
                        collection.update_one(filtre_appareil.clone(), ops, None).await?;
                    } else {
                        repondre_certificat = true;
                    }
                } else {
                    repondre_certificat = true;
                }

                if repondre_certificat {
                    debug!("Repondre avec le certificat");
                    let reponse = json!({"ok": true, "certificat": c});
                    return Ok(Some(middleware.formatter_reponse(reponse, None)?));
                }
            },
            None => {
                // Rien a faire, on a conserve le certificat
            }
        }

    } else {
        error!("commande_inscrire_appareil Erreur db - document pas insere");
    }

    let reponse = json!({"ok": true});
    return Ok(Some(middleware.formatter_reponse(reponse, None)?));
}

async fn commande_signer_appareil<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("commande_signer_appareil Consommer requete : {:?}", & m.message);
    let mut commande: CommandeSignerAppareil = m.message.get_msg().map_contenu(None)?;
    debug!("commande_signer_appareil Commande mappee : {:?}", commande);

    let user_id = match m.get_user_id() {
        Some(inner) => inner,
        None => {
            let reponse = json!({"ok": false, "err": "user_id manquant"});
            return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
        }
    };

    let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;

    let filtre_appareil = doc! {
        "uuid_appareil": &commande.uuid_appareil,
        "user_id": &user_id,
    };

    let mut doc_appareil = {
        let d = collection.find_one(filtre_appareil.clone(), None).await?;
        match d {
            Some(d) => {
                let doc_appareil: DocAppareil = convertir_bson_deserializable(d)?;
                doc_appareil
            },
            None => {
                let reponse = json!({"ok": false, "err": "appareil inconnu"});
                return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
            }
        }
    };

    let certificat = match doc_appareil.certificat {
        Some(c) => c,
        None => {
            let csr = match doc_appareil.csr {
                Some(c) => c,
                None => {
                    let reponse = json!({"ok": false, "err": "csr absent"});
                    return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
                }
            };
            debug!("commande_signer_appareil Aucun certificat, faire demande de signature");
            let routage = RoutageMessageAction::builder("CorePki", "signerCsr")
                .exchanges(vec![Securite::L3Protege])
                .build();
            let requete = json!({
                "csr": csr,  // &doc_appareil.csr,
                "roles": ["senseurspassifs"],
                "user_id": user_id,
            });
            debug!("Requete demande signer appareil : {:?}", requete);
            let reponse: ReponseCertificat = match middleware.transmettre_commande(routage, &requete, true).await? {
                Some(r) => match r {
                    TypeMessage::Valide(m) => m.message.parsed.map_contenu(None)?,
                    _ => {
                        let reponse = json!({"ok": false, "err": "Reponse certissuer invalide"});
                        return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
                    }
                },
                None => {
                    let reponse = json!({"ok": false, "err": "Aucune reponse"});
                    return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
                }
            };

            debug!("Reponse : {:?}", reponse);
            if let Some(true) = reponse.ok {

                let (certificat, fingerprint) = match &reponse.certificat {
                    Some(c) => {
                        let cert_x509 = charger_certificat(c[0].as_str());
                        (c.to_owned(), calculer_fingerprint(&cert_x509)?)
                    },
                    None => {
                        let reponse = json!({"ok": false, "err": "Reponse serveur incorrect (cert)"});
                        return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
                    }
                };

                let ops = doc! {
                    "$set": {
                        "certificat": &reponse.certificat,
                        "fingerprint": fingerprint,
                    },
                    "$unset": {"csr": true},
                    "$currentDate": {CHAMP_MODIFICATION: true},
                };
                collection.update_one(filtre_appareil, ops, None).await?;

                certificat  // Retourner certificat via reponse
            } else {
                let reponse = json!({"ok": false, "err": "Reponse serveur incorrect (ok=false)"});
                return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
            }
        }
    };

    debug!("Repondre avec certificat");
    let reponse = json!({
        "ok": true,
        "certificat": certificat,
    });

    Ok(Some(middleware.formatter_reponse(reponse, None)?))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReponseCertificat {
    ok: Option<bool>,
    certificat: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeInscrireAppareil {
    uuid_appareil: String,
    instance_id: String,
    user_id: String,
    cle_publique: String,
    csr: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeSignerAppareil {
    uuid_appareil: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DocAppareil {
    uuid_appareil: String,
    instance_id: String,
    cle_publique: Option<String>,
    csr: Option<String>,
    certificat: Option<Vec<String>>,
    fingerprint: Option<String>,
}

async fn commande_challenge_appareil<M>(middleware: &M, m: MessageValideAction, gestionnaire: &GestionnaireSenseursPassifs)
    -> Result<Option<MessageMilleGrille>, Box<dyn Error>>
    where M: GenerateurMessages + MongoDao + VerificateurMessage,
{
    debug!("commande_challenge_appareil Consommer requete : {:?}", & m.message);
    let mut commande: CommandeChallengeAppareil = m.message.get_msg().map_contenu(None)?;
    debug!("commande_challenge_appareil Commande mappee : {:?}", commande);

    let user_id = match m.get_user_id() {
        Some(inner) => inner,
        None => {
            let reponse = json!({"ok": false, "err": "user_id manquant"});
            return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
        }
    };

    let collection = middleware.get_collection(COLLECTIONS_APPAREILS)?;

    let doc_appareil_option = {
        let filtre = doc! {"uuid_appareil": &commande.uuid_appareil, "user_id": user_id};
        collection.find_one(filtre, None).await?
    };

    let doc_appareil: DocAppareil = match doc_appareil_option {
        Some(d) => convertir_bson_deserializable(d)?,
        None => {
            let reponse = json!({"ok": false, "err": "Appareil inconnu"});
            return Ok(Some(middleware.formatter_reponse(&reponse, None)?));
        }
    };

    // Emettre la commande de challenge
    let message_challenge = json!({
        "ok": true,
        "uuid_appareil": &commande.uuid_appareil,
        "challenge": &commande.challenge,
        "cle_publique": doc_appareil.cle_publique,
        "fingerprint": doc_appareil.fingerprint,
    });
    let routage = RoutageMessageAction::builder("senseurspassifs_relai", "challengeAppareil")
        .partition(doc_appareil.instance_id)
        .exchanges(vec![Securite::L2Prive])
        .build();
    middleware.transmettre_commande(routage, &message_challenge, false).await?;

    return Ok(middleware.reponse_ok()?)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CommandeChallengeAppareil {
    uuid_appareil: String,
    challenge: Vec<u8>,
}

// #[cfg(test)]
// mod test_integration {
//     use std::convert::TryFrom;
//     use millegrilles_common_rust::backup::CatalogueHoraire;
//     use millegrilles_common_rust::formatteur_messages::MessageSerialise;
//     use millegrilles_common_rust::generateur_messages::RoutageMessageAction;
//     use millegrilles_common_rust::middleware::IsConfigurationPki;
//     use millegrilles_common_rust::middleware_db::preparer_middleware_db;
//     use millegrilles_common_rust::mongo_dao::convertir_to_bson;
//     use millegrilles_common_rust::rabbitmq_dao::TypeMessageOut;
//     use millegrilles_common_rust::recepteur_messages::TypeMessage;
//     use millegrilles_common_rust::tokio as tokio;
//
//     use crate::test_setup::setup;
//
//     use super::*;
//
//     const DUMMY_INSTANCE_ID: &str = "43eee47d-fc23-4cf5-b359-70069cf06600";
//
//     #[tokio::test]
//     async fn test_requete_liste_noeuds() {
//         setup("test_requete_liste_noeuds");
//         let (middleware, _, _, _, mut futures) = preparer_middleware_db(Vec::new(), None);
//         let enveloppe_privee = middleware.get_enveloppe_privee();
//         let fingerprint = enveloppe_privee.fingerprint().as_str();
//
//         let gestionnaire = GestionnaireSenseursPassifs { instance_id: DUMMY_INSTANCE_ID.into()};
//         futures.push(tokio::spawn(async move {
//
//             let contenu = json!({});
//             let message_mg = MessageMilleGrille::new_signer(
//                 enveloppe_privee.as_ref(),
//                 &contenu,
//                 DOMAINE_NOM.into(),
//                 REQUETE_LISTE_NOEUDS.into(),
//                 None::<&str>,
//                 None
//             ).expect("message");
//             let mut message = MessageSerialise::from_parsed(message_mg).expect("serialise");
//
//             // Injecter certificat utilise pour signer
//             message.certificat = Some(enveloppe_privee.enveloppe.clone());
//
//             let mva = MessageValideAction::new(
//                 message, "dummy_q", "routing_key", "domaine", "action", TypeMessageOut::Requete);
//
//             let reponse = requete_liste_noeuds(middleware.as_ref(), mva, &gestionnaire).await.expect("dechiffrage");
//             debug!("test_requete_liste_noeuds Reponse : {:?}", reponse);
//
//             assert_eq!(true, reponse.is_some());
//
//         }));
//         // Execution async du test
//         futures.next().await.expect("resultat").expect("ok");
//     }
//
//     #[tokio::test]
//     async fn test_requete_liste_senseurs_par_uuid() {
//         setup("test_requete_liste_senseurs_par_uuid");
//         let (middleware, _, _, _, mut futures) = preparer_middleware_db(Vec::new(), None);
//         let enveloppe_privee = middleware.get_enveloppe_privee();
//         let fingerprint = enveloppe_privee.fingerprint().as_str();
//
//         let gestionnaire = GestionnaireSenseursPassifs { instance_id: DUMMY_INSTANCE_ID.into()};
//         futures.push(tokio::spawn(async move {
//
//             let contenu = json!({"uuid_senseurs": vec!["7a2764fa-c457-4f25-af0d-0fc915439b21"]});
//             let message_mg = MessageMilleGrille::new_signer(
//                 enveloppe_privee.as_ref(),
//                 &contenu,
//                 DOMAINE_NOM.into(),
//                 REQUETE_LISTE_NOEUDS.into(),
//                 None::<&str>,
//                 None
//             ).expect("message");
//             let mut message = MessageSerialise::from_parsed(message_mg).expect("serialise");
//
//             // Injecter certificat utilise pour signer
//             message.certificat = Some(enveloppe_privee.enveloppe.clone());
//
//             let mva = MessageValideAction::new(
//                 message, "dummy_q", "routing_key", "domaine", "action", TypeMessageOut::Requete);
//
//             let reponse = requete_liste_senseurs_par_uuid(middleware.as_ref(), mva, &gestionnaire).await.expect("dechiffrage");
//             debug!("test_requete_liste_senseurs_par_uuid Reponse : {:?}", reponse);
//
//             assert_eq!(true, reponse.is_some());
//
//         }));
//         // Execution async du test
//         futures.next().await.expect("resultat").expect("ok");
//     }
//
//     #[tokio::test]
//     async fn test_requete_liste_senseurs_pour_noeud() {
//         setup("test_requete_liste_senseurs_pour_noeud");
//         let (middleware, _, _, _, mut futures) = preparer_middleware_db(Vec::new(), None);
//         let enveloppe_privee = middleware.get_enveloppe_privee();
//         let fingerprint = enveloppe_privee.fingerprint().as_str();
//
//         let gestionnaire = GestionnaireSenseursPassifs { instance_id: DUMMY_INSTANCE_ID.into()};
//         futures.push(tokio::spawn(async move {
//
//             let contenu = json!({"instance_id": "48c7c654-b896-4362-a5a1-9b2c7cfdf5c4"});
//             let message_mg = MessageMilleGrille::new_signer(
//                 enveloppe_privee.as_ref(),
//                 &contenu,
//                 DOMAINE_NOM.into(),
//                 REQUETE_LISTE_NOEUDS.into(),
//                 None::<&str>,
//                 None
//             ).expect("message");
//             let mut message = MessageSerialise::from_parsed(message_mg).expect("serialise");
//
//             // Injecter certificat utilise pour signer
//             message.certificat = Some(enveloppe_privee.enveloppe.clone());
//
//             let mva = MessageValideAction::new(
//                 message, "dummy_q", "routing_key", "domaine", "action", TypeMessageOut::Requete);
//
//             let reponse = requete_liste_senseurs_pour_noeud(middleware.as_ref(), mva, &gestionnaire)
//                 .await.expect("requete");
//             debug!("test_requete_liste_senseurs_pour_noeud Reponse : {:?}", reponse);
//
//             assert_eq!(true, reponse.is_some());
//
//         }));
//         // Execution async du test
//         futures.next().await.expect("resultat").expect("ok");
//     }
//
//     #[tokio::test]
//     async fn test_requete_get_noeud() {
//         setup("test_requete_get_noeud");
//         let (middleware, _, _, _, mut futures) = preparer_middleware_db(Vec::new(), None);
//         let enveloppe_privee = middleware.get_enveloppe_privee();
//         let fingerprint = enveloppe_privee.fingerprint().as_str();
//
//         let gestionnaire = GestionnaireSenseursPassifs { instance_id: DUMMY_INSTANCE_ID.into()};
//         futures.push(tokio::spawn(async move {
//
//             let contenu = json!({"instance_id": "48c7c654-b896-4362-a5a1-9b2c7cfdf5c4"});
//             let message_mg = MessageMilleGrille::new_signer(
//                 enveloppe_privee.as_ref(),
//                 &contenu,
//                 DOMAINE_NOM.into(),
//                 REQUETE_LISTE_NOEUDS.into(),
//                 None::<&str>,
//                 None
//             ).expect("message");
//             let mut message = MessageSerialise::from_parsed(message_mg).expect("serialise");
//
//             // Injecter certificat utilise pour signer
//             message.certificat = Some(enveloppe_privee.enveloppe.clone());
//
//             let mva = MessageValideAction::new(
//                 message, "dummy_q", "routing_key", "domaine", "action", TypeMessageOut::Requete);
//
//             let reponse = requete_get_noeud(middleware.as_ref(), mva, &gestionnaire)
//                 .await.expect("requete");
//             debug!("test_requete_liste_senseurs_pour_noeud Reponse : {:?}", reponse);
//
//             assert_eq!(true, reponse.is_some());
//
//         }));
//         // Execution async du test
//         futures.next().await.expect("resultat").expect("ok");
//     }
//
//     #[tokio::test]
//     async fn test_transaction_suppression_senseur() {
//         setup("test_requete_get_noeud");
//         let (middleware, _, _, _, mut futures) = preparer_middleware_db(Vec::new(), None);
//         let enveloppe_privee = middleware.get_enveloppe_privee();
//         let fingerprint = enveloppe_privee.fingerprint().as_str();
//
//         let gestionnaire = GestionnaireSenseursPassifs { instance_id: DUMMY_INSTANCE_ID.into()};
//         futures.push(tokio::spawn(async move {
//
//             let contenu = json!({"uuid_senseur": "7a2764fa-c457-4f25-af0d-0fc915439b21"});
//             let message_mg = MessageMilleGrille::new_signer(
//                 enveloppe_privee.as_ref(),
//                 &contenu,
//                 DOMAINE_NOM.into(),
//                 REQUETE_LISTE_NOEUDS.into(),
//                 None::<&str>,
//                 None
//             ).expect("message");
//             let mut message = MessageSerialise::from_parsed(message_mg).expect("serialise");
//
//             // Injecter certificat utilise pour signer
//             message.certificat = Some(enveloppe_privee.enveloppe.clone());
//
//             let transaction = TransactionImpl::try_from(message).expect("treansaction");
//
//             let reponse = transaction_suppression_senseur(middleware.as_ref(), transaction, &gestionnaire)
//                 .await.expect("requete");
//             debug!("test_transaction_suppression_senseur Reponse : {:?}", reponse);
//
//             assert_eq!(true, reponse.is_some());
//
//         }));
//         // Execution async du test
//         futures.next().await.expect("resultat").expect("ok");
//     }
//
//         #[tokio::test]
//     async fn test_transaction_lectures() {
//         setup("test_transaction_lectures");
//         let (middleware, _, _, _, mut futures) = preparer_middleware_db(Vec::new(), None);
//         let enveloppe_privee = middleware.get_enveloppe_privee();
//         let fingerprint = enveloppe_privee.fingerprint().as_str();
//
//         let gestionnaire = GestionnaireSenseursPassifs { instance_id: DUMMY_INSTANCE_ID.into()};
//         futures.push(tokio::spawn(async move {
//
//             // Attendre connexion MQ
//             tokio::time::sleep(tokio::time::Duration::new(2, 0)).await;
//
//             let contenu = json!({
//                 "uuid_senseur": "7d32d355-d3fa-44fd-8a4d-323580fe55e2:dht",
//                 "instance_id": "7d32d355-d3fa-44fd-8a4d-323580fe55e2",
//                 "senseur": "dht/18/temperature",
//                 "avg": 22.7,
//                 "max": 22.8,
//                 "min": 22.6,
//                 "timestamp": 1631156400,
//                 "timestamp_max": 1631159993,
//                 "timestamp_min": 1631156413,
//                 "type": "temperature",
//                 "lectures": [
//                     {"timestamp": 1631156413, "valeur": 22.8},
//                     {"timestamp": 1631156428, "valeur": 22.6},
//                     {"timestamp": 1631156444, "valeur": 22.7}
//                 ]
//             });
//             let message_mg = MessageMilleGrille::new_signer(
//                 enveloppe_privee.as_ref(),
//                 &contenu,
//                 DOMAINE_NOM.into(),
//                 REQUETE_LISTE_NOEUDS.into(),
//                 None::<&str>,
//                 None
//             ).expect("message");
//             let mut message = MessageSerialise::from_parsed(message_mg).expect("serialise");
//
//             // Injecter certificat utilise pour signer
//             message.certificat = Some(enveloppe_privee.enveloppe.clone());
//
//             let transaction = TransactionImpl::try_from(message).expect("transaction");
//
//             let reponse = transaction_lectures(middleware.as_ref(), transaction, &gestionnaire)
//                 .await.expect("requete");
//             debug!("test_transaction_lectures Reponse : {:?}", reponse);
//
//             assert_eq!(true, reponse.is_some());
//
//         }));
//         // Execution async du test
//         futures.next().await.expect("resultat").expect("ok");
//     }
// }
