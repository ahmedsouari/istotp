# Audit ISO 14229-1:2020 - Service 0x27 SecurityAccess

## Resume executif
La mise en oeuvre actuelle du service SecurityAccess fournit un flux seed/key fonctionnel et integre la generation de seed aleatoire ainsi qu une verification HMAC cote serveur. Malgre cela, plusieurs exigences critiques de l ISO 14229-1:2020 restent non couvertes ou detournees, ce qui place la conformite globale en statut partiel.

Les risques majeurs portent sur l absence de remise a zero de l automate apres une cle invalide, la possibilite de court-circuiter le temporisateur anti brute force en redemandant immediatement un seed, et l ignorance du suppressPosRspMsgIndicationBit. Ces ecarts ouvrent la voie a des attaques par devinette rapide, a des erreurs d interop, et a des difficultes de certification.

## Checklist de conformite 0x27
| Exigence | Statut | Preuve (fichier:ligne) | Commentaire / Action |
| --- | --- | --- | --- |
| Objectif & automate seed/key | - [ ] Fail | `src/lib/uds_server/src/services/uds_0x27_secur_access.cpp:195-307` | Sequence remise a zero uniquement en cas de succes (ligne 277) : apres un 0x35 le client peut rejouer `27 02` sans `27 01`, contrairement a l ISO qui exige une nouvelle demande de seed. |
| Parite des sous-fonctions | - [ ] Fail | `src/lib/uds_server/src/services/uds_0x27_secur_access.cpp:83-92`<br>`src/lib/uds_server/src/services/uds_0x27_secur_access.cpp:318-327` | Le filtre reserve applique `0x3F` et laisse passer 0x43..0x5E et 0x7F; `27 41` obtient un seed au lieu d un 7F 27 12. |
| Un seul niveau actif | - [x] Pass | `src/lib/uds_server/src/services/uds_0x27_secur_access.cpp:259-281`<br>`src/lib/uds_server/src/services/uds_0x27_secur_access.cpp:342-352` | `m_securityLevel` est unique, les observateurs sont notifies, et CustomDataServices controle les services exposes a chaque niveau. |
| Reponse positive 0x67 | - [x] Pass | `src/lib/uds_server/src/services/uds_0x27_secur_access.cpp:118-172`<br>`src/lib/uds_server/src/services/uds_0x27_secur_access.cpp:271-275`<br>`src/lib/uds_server/src/uds_message.cpp:138-186` | Structure conforme (0x67 + type + seed), seed retournee uniquement sur requestSeed; attention cependant au bit 7 et a la taille fixe de 32 octets (voir ecarts). |
| NRC 0x12/0x13/0x22/0x24/0x31/0x35/0x36/0x37 | - [ ] Fail | `src/lib/uds_server/src/services/uds_0x27_secur_access.cpp:42-80`<br>`src/lib/uds_server/src/services/uds_0x27_secur_access.cpp:195-218`<br>`src/uds_ecu_interface/custom_data_services.cpp:87-137` | 0x31 n est jamais emis, les niveaux reserves renvoient 0x13 au lieu de 0x12, et 0x37 n est jamais retourne sur requestSeed pendant la periode anti brute force. |
| Temporisations & anti brute force | - [ ] Fail | `src/lib/uds_server/src/uds_service.cpp:31-44`<br>`src/lib/uds_server/src/services/uds_0x27_secur_access.cpp:205-305`<br>`src/lib/uds_server/config/uds_config.hpp:259-273` | Le fail timer lance par `UDS_SECURITY_ACCESS_FAILED_TIMEOUT` n est jamais consulte dans `handleRequestSeed`, ce qui autorise un nouveau seed pendant la penalite. |
| SuppressPosRspMsgIndicationBit | - [ ] Fail | `src/lib/uds_server/src/services/uds_0x27_secur_access.cpp:83-92`<br>`src/lib/uds_server/src/services/uds_0x27_secur_access.cpp:118-172`<br>`src/lib/uds_server/src/services/uds_0x27_secur_access.cpp:272-275` | Le bit 7 n est jamais teste et les reponses positives sont toujours emises meme quand la suppression est demandee; aucune distinction entre adressage physique et fonctionnel. |
| Exemples de trames seed/key | - [ ] Fail | `src/lib/uds_server/config/uds_config.hpp:288-300`<br>`src/lib/uds_server/src/uds_security_handler.cpp:103-139` | Seed et key sont figees a 32 octets et calculees via HMAC; on ne peut pas reproduire les trames d exemple `3657`/`C9A9` sans modifier le handler et la configuration. |

## Flux et formats
- **Dispatch** : `UdsService::handleRequest` detourne les SID vers `handleSecurityAccess` (`src/lib/uds_server/src/uds_service.cpp:212-239`).
- **Request Seed** : `handleRequestSeed` extrait la sous-fonction, vide la liste des services autorises, verifie le support via `CustomDataServices::IsSecurityAccessLeveLSupported`, puis genere `UDS_0x27_SEED_SIZE` octets (`src/lib/uds_server/src/services/uds_0x27_secur_access.cpp:118-169`). Le `securityAccessDataRecord` est seulement stocke (`src/lib/uds_server/src/uds_security_handler.cpp:142-145`) et jamais valide.
- **Send Key** : `handleSendKey` exige `subFunction_even == last_seed + 1` avant de valider la cle (`src/lib/uds_server/src/services/uds_0x27_secur_access.cpp:195-227`). La cle attendue est un HMAC-SHA256 du seed avec la cle secrete lue dans `UDS_SECURITY_ACCESS_SYM_KEY_PATH` (`src/lib/uds_server/src/uds_security_handler.cpp:103-139`).
- **Coloration des reponses** : `UdsMessage::encodePayload` ajoute `0x40` au SID en cas de succes et construit les trames negatives `7F <SID> <NRC>` (`src/lib/uds_server/src/uds_message.cpp:138-186`).

## Gestion des erreurs / NRC
| NRC | Condition implemente | Preuve (fichier:ligne) | Test minimal |
| --- | --- | --- | --- |
| 0x12 | Niveau non supporte via CustomDataServices | `src/uds_ecu_interface/custom_data_services.cpp:87-104` | Envoyer `27 07` -> attendu `7F 27 12` (OK). |
| 0x13 | Donnee vide | `src/lib/uds_server/src/services/uds_0x27_secur_access.cpp:42-49` | Envoyer `27` -> `7F 27 13` (OK). |
| 0x22 | Services non disponibles pour le niveau | `src/uds_ecu_interface/custom_data_services.cpp:113-137` | Forcer un niveau inconnu (ex: manipuler config) -> devrait renvoyer `7F 27 22`. |
| 0x24 | SendKey hors sequence | `src/lib/uds_server/src/services/uds_0x27_secur_access.cpp:195-201` | `27 04` sans `27 03` -> `7F 27 24` (OK). |
| 0x31 | Non implemente (dataRecord jamais valide) | `src/lib/uds_server/src/services/uds_0x27_secur_access.cpp:139-145` | `27 01 00` ou `27 02` avec longueur != 32 -> renvoie 0x67/0x35 au lieu de `7F 27 31`. |
| 0x35 | Cle invalide | `src/lib/uds_server/src/services/uds_0x27_secur_access.cpp:286-305` | `27 01` puis `27 02` avec HMAC faux -> `7F 27 35` (OK). |
| 0x36 | Nombre maxi d essais atteint | `src/lib/uds_server/src/services/uds_0x27_secur_access.cpp:205-218` | Rejouer 3 clefs fausses puis `27 02` -> `7F 27 36` (OK). |
| 0x37 | Temporisateur non expire | `src/lib/uds_server/src/services/uds_0x27_secur_access.cpp:73-80` | Immediatement apres reset serveur `27 01` -> `7F 27 37`; pendant le fail timer un `27 01` renvoie encore un seed (KO). |

## Temporisations & anti-brute-force
- **Boot timer** : cree dans le constructeur (`src/lib/uds_server/src/uds_service.cpp:31-44`) avec `UDS_SERVER_POWER_UP_TIMEOUT` par defaut a 2 s (`src/lib/uds_server/config/uds_config.hpp:279-282`); toute requete tant que le timer n a pas expire renvoie 0x37.
- **Fail timer** : `m_NbOfSecurityAccessFailed` compte les essais (`src/lib/uds_server/src/services/uds_0x27_secur_access.cpp:292-305`). Au seuil `UDS_MAX_NUMBER_OF_SECURITY_ACCESS_FAILED` (3) un timer de 5 s (`UDS_SECURITY_ACCESS_FAILED_TIMEOUT`) est demarre.
- **Ecarts** :
  - `handleRequestSeed` ne consulte jamais `m_SecurityAccessFailTimer`; pendant la penalite un attaquant peut obtenir un nouveau seed et recomposer une cle -> bypass du 0x37.
  - `m_securityAccessSequence` n est pas reinitialise apres 0x35, autorisant un `27 02` immediat sans nouvelle graine.
  - `m_isfirstStartFailTimer` reste `true` apres expiration du timer; sans lecture explicite du timerfd, `isTimerExpired` renvoie toujours `true` et le flag n est jamais remis a zero hors `resetSecurityAccessParams`.

## Ecarts & recommandations
- **P1** Renforcer l automate seed/key : reinitialiser `m_securityAccessSequence` apres 0x35 et bloquer `handleRequestSeed` tant que le fail timer est actif. Exemple de correctif :
  ```
*** Update File: src/lib/uds_server/src/services/uds_0x27_secur_access.cpp
@@
-        p_response->setResponseCode( udsmessage::UdsMessageRetCode::InvalidKey );
-        m_NbOfSecurityAccessFailed++;
+        p_response->setResponseCode( udsmessage::UdsMessageRetCode::InvalidKey );
+        m_securityAccessSequence = 0U; /* force un nouveau requestSeed */
+        m_NbOfSecurityAccessFailed++;
@@
-    /* Extract the security access data record from the request. */
+    bool failTimerExpired = true;
+    if ( m_isfirstStartFailTimer == true )
+    {
+        (void)interface::os::isTimerExpired( m_SecurityAccessFailTimer, &failTimerExpired );
+    }
+    if ( ( m_isfirstStartFailTimer == true ) && ( failTimerExpired == false ) )
+    {
+        p_response->setResponseCode( udsmessage::UdsMessageRetCode::RequiredTimeDelayNotExpired );
+        return;
+    }
+    /* Extract the security access data record from the request. */
  ```
- **P1** Corriger la detection des sous-fonctions reservees et renvoyer 0x12 :
  ```
*** Update File: src/lib/uds_server/src/services/uds_0x27_secur_access.cpp
@@
-    uint8_t securityLevel = subFunction & 0x3FU;
-    if ( ( 0U == securityLevel ) || ( ( securityLevel >= 0x43U ) && ( securityLevel <= 0x5EU ) ) || ( securityLevel == 0x7FU ) )
+    uint8_t securityAccessType = subFunction & 0x7FU;
+    if ( ( securityAccessType == 0U ) || ( ( securityAccessType >= 0x43U ) && ( securityAccessType <= 0x5EU ) ) ||
+         ( securityAccessType == 0x7FU ) )
  ```
- **P1** Introduire un controle du `securityAccessDataRecord` (taille attendue, valeur) et repondre 0x31 lorsque le contenu est invalide.
- **P2** Prendre en compte `SuppressPosRspMsgIndicationBit` : ignorer les reponses positives pour les requetes physiques avec bit 7 a 1, et s assurer que les negatives sont toujours emises.
- **P2** Nettoyer le bit 7 dans les reponses positives (`response_data[0] = subFunction & 0x7FU`) pour rester conforme aux testers qui n attendent que le type.
- **P3** Documenter ou parametrer l algorithme seed/key : le guide client propose une cle en complement a deux alors que l implementation impose un HMAC 32 octets; aligner la specification interne ou offrir un hook de calcul.

## Tests suggeres
- **Nominal** : `27 01` -> `67 01` + 32 octets de seed puis `27 02 <HMAC(seed)>` -> `67 02`. Verifier que `m_securityLevel` passe a 0x01 et que les services proteges sont accessibles.
- **Sequence invalide** : `27 02` sans seed prealable -> `7F 27 24`.
- **Cle invalide** : `27 01` puis `27 02` avec HMAC faux -> `7F 27 35`; rejouer jusqu au seuil pour observer `7F 27 36`.
- **Temporisateur anti brute force** : apres 3 echecs, `27 01` doit renvoyer `7F 27 37` (actuellement renvoie un nouveau seed).
- **Longueur incorrecte** : `27 02` avec 1 octet -> attendu `7F 27 13` ou `7F 27 31`, retour observe `7F 27 35`.
- **Sous-fonction reservee** : `27 41` -> attendu `7F 27 12`, retour observe `67 41` + seed.
- **Suppression reponse** : `27 81` sur adresse physique -> attendu absence de reponse positive, retour observe `67 81`.

## Cartographie du code
| Bloc | Fichier (ligne) | Notes |
| --- | --- | --- |
| Dispatch UDS | `src/lib/uds_server/src/uds_service.cpp:212-239` | Selection du handler selon le SID. |
| Handler SecurityAccess | `src/lib/uds_server/src/services/uds_0x27_secur_access.cpp:29-397` | Automate seed/key, compteurs, reset. |
| SecurityHandler | `src/lib/uds_server/src/uds_security_handler.cpp:90-305`<br>`src/lib/uds_server/include/uds_security_handler.hpp` | Generation du seed, calcul/verification HMAC, lecture de la cle secrete. |
| Politique niveaux | `src/uds_ecu_interface/custom_data_services.cpp:87-141`<br>`src/uds_ecu_interface/custom_data_services.hpp:38-43` | Definition des niveaux disponibles et des services associes. |
| Configuration | `src/lib/uds_server/config/uds_config.hpp:259-308` | Parametres seed/key, timeouts, chemins de cle. |
| Timers OS | `src/lib/port/src/port_linux.cpp:267-316` | Implementation `timerStart/isTimerExpired/timerStop`. |
| Tests unitaires | `test/unit_tests/src/uds_server/services/uds_security_access_test.cpp` | Couverture partielle; a completer selon les scenarios suggeres. |

## Guide de revue rapide
- **Build** : `cmake -S src -B build -DUNIT_TESTS=ON` puis `cmake --build build`.
- **Tests** : `ctest --test-dir build -R SecurityAccess --output-on-failure` pour cibler les tests GTest existants.
- **Parametrage cle** : adapter `UDS_SECURITY_ACCESS_SYM_KEY_PATH` (config `src/lib/uds_server/config/uds_config.hpp`) vers un emplacement securise avant de lancer des tests d integrite.
- **Debogage timers** : les tests unitaires peuvent forcer l expiration via `interface::os::setTimerExpiredForTest`; reutiliser cette approche pour valider les correctifs 0x36/0x37.
- **Campagne manuelle** : utiliser un client DoIP/UDS pour rejouer les trames referencees ci-dessus et verifier les modifications sur l automate de securite.
