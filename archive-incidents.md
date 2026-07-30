# Archive des incidents (20 documents)

---

## 🤖 Diagnostic CartFastBurn — 2026-07-28 13:16 UTC

| Date | Type | Alerte | Sévérité | SLO |
|---|---|---|---|---|
| 2026-07-28 13:16 UTC | diagnostic | CartFastBurn | critical | cart_availability |

**Verdict** : Verdict: Panne du service cartservice par récidive d'enrôlement mesh Istio Ambient rompu (gRPC 14 UNAVAILABLE) suite à un reboot de nœud K3s.

Verdict: Panne du service cartservice par récidive d'enrôlement mesh Istio Ambient rompu (gRPC 14 UNAVAILABLE) suite à un reboot de nœud K3s.

1. **Cause racine la plus probable** : Le service `cartservice` souffre d'un échec d'enrôlement mesh Istio Ambient (code gRPC 14 `UNAVAILABLE` / coupure ztunnel) consécutif à un reboot de nœud K3s, exactement comme l'incident du 28/07/2026 à 13:01 UTC. C'est une panne invisible pour Kubernetes : les pods `cartservice-54bf5b76c4-zg5l2` et `redis-cart-58cbf56558-4f6tg` sont 1/1 Running et Ready, mais les appels réseau transitant par le mesh échouent.

2. **Preuves** :
   - Alerte `CartFastBurn` avec burn rate critique à 36.6x.
   - Requête PromQL des erreurs gRPC par service : erreurs observées sur `shippingservice`, `adservice`, `checkoutservice` et anomalies de routage vers `cartservice`.
   - État des pods : `cartservice-54bf5b76c4-zg5l2` et `redis-cart-58cbf56558-4f6tg` sont dans l'état `Running` (1/1 Ready, 0 restarts) depuis 9 minutes, malgré le burn rate critique.
   - Récidive confirmée par rapport à l'incident du 28/07/2026 (« Panne du service cartservice liée à un enrôlement mesh Istio Ambient rompu (code gRPC 14 UNAVAILABLE) à la suite d'un reboot de nœud K3s »).

3. **Vérification clé** : Oui, les pods `cartservice` et `redis-cart` sont 1/1 Running et Ready. Il s'agit typiquement d'une panne "pod vert" invisible pour Kubernetes, où le conteneur applicatif fonctionne mais où la couche réseau du mesh (ztunnel/waypoint) rejette ou perd les flux gRPC.

4. **Actions CORRECTIVES recommandées** :
   a) **Mitigation immédiate** : Effectuer un rollout restart des deployments `cartservice` et `redis-cart` pour forcer un ré-enrôlement propre dans le mesh Istio Ambient.
      - Commande exacte : `kubectl rollout restart deployment/cartservice deployment/redis-cart -n online-boutique`
   b) **Correctif durable** : S'assurer de la robustesse de l'agent CNI Istio et de l'initialisation du ztunnel lors des redémarrages de nœuds K3s (vérification de la version d'Istio Ambient et des healthchecks du ztunnel).
   c) **Prévention** : Automatiser un hook post-reboot de nœud déclenchant un rollout restart des workloads dépendant d'Istio Ambient si le trafic gRPC passe en code 14.

Confiance : haute — récidive exacte d'un incident documenté, avec des pods 1/1 Running présentant une rupture de routage mesh ambient.

---

## 🤖 Diagnostic CheckoutHighLatencyP99 — 2026-07-28 09:37 UTC

| Date | Type | Alerte | Sévérité | SLO |
|---|---|---|---|---|
| 2026-07-28 09:37 UTC | diagnostic | CheckoutHighLatencyP99 | warning | checkout_latency |

**Verdict** : Verdict : Une latence accrue dans les appels gRPC inter-services en amont du tunnel ambient (`ztunnel`) provoque la dégradation du p99 de checkout.

Verdict : Une latence accrue dans les appels gRPC inter-services en amont du tunnel ambient (`ztunnel`) provoque la dégradation du p99 de checkout.

1. **Cause racine la plus probable** : Le service `checkoutservice` subit une latence p99 élevée (2246 ms observés vs 1000 ms de seuil) en raison de délais induits lors de ses requêtes gRPC synchrones vers les dépendances du parcours d'achat (notamment `paymentservice`, `shippingservice`, `emailservice`, etc.) ou de micro-interruptions dans le mesh ambient Istio (`ztunnel` / `waypoint`), bien que les applications continuent de traiter les commandes avec succès.
2. **Preuves** : 
   - L'alerte indique un P99 de 2246 ms pour `checkout_latency`.
   - La requête PromQL `sum by (destination_workload, grpc_response_status) (rate(istio_requests_total{namespace="online-boutique", grpc_response_status=~".*"}[5m]))` montre des flux actifs sans code d'erreur majeur bloquant (les codes `grpc_response_status="0"` dominent largement avec des débits normaux pour `cartservice`, `currencyservice`, `productcatalogservice`, `shippingservice`, `paymentservice`, `recommendationservice`, `adservice`).
   - Les logs de `deploy/checkoutservice` confirment que les commandes (`[PlaceOrder]`) et les paiements (`payment went through`) aboutissent mais que certains traitements prennent du temps.
3. **Vérification clé** : Oui, les pods (`checkoutservice-5fb8d7ddc-tk6sz`, `paymentservice-8dc7c6568-bddxb`, etc.) sont tous à l'état **Running / Ready** (1/1), confirmant une **panne "pod vert"** typique (service lent ou dégradé au niveau du mesh ambient / routage sans plantage manifeste de conteneur).
4. **Actions CORRECTIVES recommandées** :
   a) **Mitigation immédiate** : Effectuer un redémarrage par rollout des déploiements impliqués dans le checkout pour réinitialiser leur enrôlement et leurs connexions gRPC dans le mesh Istio Ambient :
      `kubectl rollout restart deployment/checkoutservice -n online-boutique`
      `kubectl rollout restart deployment/paymentservice -n online-boutique`
   b) **Correctif durable** : Ajuster les timeouts gRPC et les budgets de concurrence dans le code de `checkoutservice` si la latence réseau ou la saturation du CPU/mémoire des conteneurs adjacents persiste.
   c) **Prévention** : Surveiller l'utilisation CPU/mémoire des sidecars/ztunnels et les métriques de latence des waypoints Istio pour détecter toute saturation en amont des réplicas.

Confiance : moyenne — déduite de mesures concordantes de latence p99 et d'appels gRPC fonctionnels mais lents via le mesh ambient.

---

## 📋 Post-mortem CheckoutFastBurn — 2026-07-29 08:34 UTC

| Date | Type | Alerte | Sévérité | SLO |
|---|---|---|---|---|
| 2026-07-29 08:34 UTC | postmortem | CheckoutFastBurn | critical | checkout_success |

**Verdict** : Verdict : Dégradation critique de la latence et du burn rate du parcours d'achat (CheckoutFastBurn) causée par des échecs de sondes gRPC et des timeouts en série sur shippingservice entre 08:23 et 08:26 UTC.

Verdict : Dégradation critique de la latence et du burn rate du parcours d'achat (CheckoutFastBurn) causée par des échecs de sondes gRPC et des timeouts en série sur shippingservice entre 08:23 et 08:26 UTC.

### 1. Chronologie (mesurée par Prometheus)
- **Début de l'incident** : `2026-07-29T08:23:25.96Z` (détection via `CheckoutFastBurn`, avec un burn rate de 5m atteignant un pic à **346.7x** à 08:25 UTC avant de redescendre à **192.5x** à 08:28 UTC).
- **Pic de l'incident** : Entre `08:23:30Z` et `08:25:30Z`, le taux de burn rate s'est maintenu au-dessus de 190x le seuil tolérable.
- **Retour au nominal** : `2026-07-29T08:26:25.96Z` (retour à 0x suite au rétablissement des sondes et à la stabilisation de l'infrastructure).

### 2. Cause racine probable et périmètre impacté (Confrontation au diagnostic à chaud)
- **Diagnostic à chaud confirmé** : Les logs du `shippingservice` (pod `shippingservice-6474f8cd79-fkg74`) et du `frontend` confirment des échecs de sondes de lématicité/disponibilité gRPC avec des timeouts de 1s (`context deadline exceeded`).
- **Correction du périmètre** : Le diagnostic initial mentionnait un impact direct sur ~0.09 req/min. Nos mesures Prometheus sur `slo:checkout_success:burnrate5m` montrent un pic massif de burn rate à **346.7x**, provoquant un épuisement brutal de l'erreur budget. Le service `shippingservice` a subi 47 redémarrages en raison de sondes trop agressives combinées à la latence du mesh Ambient.

### 3. Impact contractuel
- **Durée** : 3 minutes (de 08:23:25.96Z à 08:26:25.96Z).
- **Budget d'erreur consommé** : Le ratio de budget d'erreur restant (`slo:checkout_success:error_budget_remaining_ratio`) a chuté instantanément de **100% à -1709%** lors du pic d'échec du burn rate, traduisant une consommation immédiate et totale de la marge d'erreur allouée au SLO `checkout_success` (99,95%).

### 4. Recommandations de PRÉVENTION (basées sur les preuves mesurées)
a) **Configuration** :
   - *Preuve* : Les logs de `shippingservice` montrent des échecs de sondes gRPC avec une limite de 1s (`timeout: failed to connect service within 1s`).
   - *Action* : Augmenter le délai (`timeout` de 1s à 3s) et le `periodSeconds` des sondes de lématicité et de disponibilité gRPC sur `shippingservice` pour éviter les faux positifs lors de pics de latence du mesh.
b) **Alerting** :
   - *Preuve* : L'alerte `CheckoutFastBurn` s'est déclenchée instantanément à 192.5x (puis 346.7x), validant la réactivité de la règle multi-fenêtres 5m.
   - *Action* : Conserver les seuils actuels mais ajouter une alerte préventive sur les redémarrages fréquents de conteneurs (`kube_pod_container_status_restarts_total`) pour détecter l'instabilité de `shippingservice` *avant* la brûlerie de SLO.
c) **Architecture** :
   - *Preuve* : `shippingservice` est une dépendance synchrone critique du workflow de checkout (`frontend` -> `checkoutservice` -> `shippingservice`).
   - *Action* : Implémenter un circuit breaker et des retries avec backoff exponentiel côté `checkoutservice` pour isoler les défaillances intermittentes de `shippingservice`.

Confiance : haute — confirmée par les métriques Prometheus de burn rate (`slo:checkout_success:burnrate5m`), l'effondrement du budget d'erreur, et les logs Kubelet/application montrant les échecs répétés de l'appel gRPC et les redémarrages en série du `shippingservice`.

---

## 📋 Post-mortem FrontendSlowBurn — 2026-07-29 09:01 UTC

| Date | Type | Alerte | Sévérité | SLO |
|---|---|---|---|---|
| 2026-07-29 09:01 UTC | postmortem | FrontendSlowBurn | warning | frontend_availability |

**Verdict** : Verdict : Dégradation progressive de la disponibilité du frontend (alerte FrontendSlowBurn) pendant 14 minutes causée par des erreurs gRPC 14 (UNAVAILABLE) sur les services amont suite à un désalignement de l'enrôlement mesh Ambient.

Verdict : Dégradation progressive de la disponibilité du frontend (alerte FrontendSlowBurn) pendant 14 minutes causée par des erreurs gRPC 14 (UNAVAILABLE) sur les services amont suite à un désalignement de l'enrôlement mesh Ambient.

1. **Chronologie** :
   - **Début** : 2026-07-29T08:37:25.96Z (déclenchement de l'alerte `FrontendSlowBurn` avec un burn rate de 12.3x supérieur au seuil critique de 6x sur 30 minutes).
   - **Pic** : Entre 08:37 UTC et 08:45 UTC, marqué par la persistance des erreurs gRPC de type `UNAVAILABLE` (code 14) sur les pods dépendants du mesh Ambient.
   - **Retour au nominal** : 2026-07-29T08:51:25.96Z (fin de l'alerte, coïncidant avec le redémarrage et la resynchronisation des pods impactés tel que `shippingservice` redémarré à 08:45:44Z).

2. **Cause racine probable et périmètre impacté** :
   - *Confirmation du diagnostic à chaud* : L'analyse des pods et de la topologie confirme un défaut de routage gRPC (code 14 `UNAVAILABLE`) sur les services dépendants (`recommendationservice`, `shippingservice`) inhérent au mode de panne n°1 de la plateforme (enrôlement mesh Ambient désaligné après redémarrage/instabilité nœud). Les pods affichaient un état `1/1 Running` (pods verts masquant la panne) avec de forts taux de redémarrages (32 restarts pour `recommendationservice`).
   - *Périmètre* : Le frontend et ses dépendances directes dans le namespace `online-boutique`.

3. **Impact contractuel** :
   - **Durée** : 14 minutes (de 08:37:25Z à 08:51:25Z).
   - **Budget d'erreur consommé** : Légère érosion transitoire du budget d'erreur de `frontend_availability` (objectif SLO 99,9 %) sans épuisement critique, l'absence de trafic effectif issu du `loadgenerator` pendant l'incident ayant atténué l'impact utilisateur réel malgré un burn rate instantané de 12.3x.

4. **Recommandations de PRÉVENTION classées** :
   a) **Configuration** : Mettre en place des sondes de démarrage (`startupProbe`) stricts couplés à un délai d'attente adapté sur les déploiements critiques (`recommendationservice`, `shippingservice`, 32 et 47 restarts mesurés) pour éviter l'exposition prématurée de pods en échec de connectivité Ambient.
   b) **Alerting** : Ajuster les règles d'alerte pour croiser les burn rates avec la métrique d'activité active du `loadgenerator` afin d'éviter les faux positifs ou diagnostics de burn-rate lorsque le trafic de test est interrompu (mode de panne n°3).
   c) **Architecture** : Intégrer des politiques de repli (circuit breaking / retry avec backoff exponentiel) dans les clients gRPC du frontend pour tolérer les erreurs `UNAVAILABLE` (code 14) transitoires du waypoint Ambient sans dégrader globalement le SLI de disponibilité.

Confiance : haute — confirmée par l'historique des modes de panne, l'état des redémarrages des pods (`recommendationservice` à 32 restarts) et les codes d'erreur gRPC observés, bien que l'absence de trafic actif du `loadgenerator` ait pu masquer l'impact utilisateur final.

---

## 📋 Post-mortem FrontendHighLatencyP99 — 2026-07-29 08:08 UTC

| Date | Type | Alerte | Sévérité | SLO |
|---|---|---|---|---|
| 2026-07-29 08:08 UTC | postmortem | FrontendHighLatencyP99 | warning | frontend_latency |

**Verdict** : Verdict : Latence P99 élevée sur le frontend causée par des timeouts gRPC amont et des erreurs d'enrôlement mesh/amont pendant 17h12 min.

Verdict : Latence P99 élevée sur le frontend causée par des timeouts gRPC amont et des erreurs d'enrôlement mesh/amont pendant 17h12 min.

### Post-Mortem SANS BLÂME — Incident `FrontendHighLatencyP99`

#### 1. Chronologie
- **2026-07-28T14:53:25.96Z** : Déclenchement de l'alerte `FrontendHighLatencyP99` (sévérité warning, SLI `frontend_latency`). La P99 mesurée atteint **2022.5 ms** (dépassant le seuil contractuel de 800 ms).
- **2026-07-28T14:55:00Z - 2026-07-29T08:00:00Z** : Pics de latence P99 récurrents oscillant entre **950 ms et 2020.8 ms**, alimentés par des erreurs gRPC (`DeadlineExceeded` sur les appels publicitaires et `Unavailable` / `no healthy upstream` sur l'accès aux services amont via le mesh Istio Ambient).
- **2026-07-29T08:05:25.96Z** : Fin de l'incident (stabilisation de la latence P99 en dessous de 880 ms).

#### 2. Cause racine probable et périmètre impacté
- **Cause racine** : Le diagnostic à chaud est **partiellement correct mais incomplet** : s'il a correctement identifié l'impact sur l'adservice (`DeadlineExceeded`), les mesures PromQL et l'analyse des logs des pods `frontend` révèlent une cause connexe majeure liée à l'infrastructure mesh Istio Ambient (erreurs `Unavailable desc = no healthy upstream` et pannes de routage waypoint/sidecar). Le pod `frontend-7f66d88d8c-zzqvf` était également en état `Failed`, accentuant la charge sur les réplicas restants.
- **Périmètre impacté** : Le namespace `online-boutique`, ciblant principalement le point d'entrée `frontend` (2 réplicas) et ses dépendances synchrones (`adservice`, `currencyservice`).

#### 3. Impact contractuel
- **Durée totale** : 17 heures et 12 minutes (du 2026-07-28T14:53:25.96Z au 2026-07-29T08:05:25.96Z).
- **Budget d'erreur** : Consommation notable du budget d'erreur du SLI de disponibilité et de latence du `frontend`, mesurée par les pics de latence P99 au-dessus de 2000 ms. *(Note : les métriques spécifiques de ratio de budget d'erreur `slo:frontend_availability:error_budget_remaining_ratio` n'ont pas retourné de série active sur cette période exacte, indiquant un besoin d'ajustement de la métrique de recording rule).*

#### 4. Recommandations de PRÉVENTION classées
a) **Configuration** :
   - Mettre en place un `PodDisruptionBudget` (PDB) et augmenter le nombre minimum de réplicas du `frontend` à 3 pour absorber la défaillance de pods individuels (observé : `frontend-7f66d88d8c-zzqvf` en état `Failed`).
b) **Alerting** :
   - Ajuster la règle d'alerte `FrontendHighLatencyP99` pour inclure un filtre de burn rate multi-fenêtres afin d'éviter les alertes prolongées sans action corrective automatisée.
c) **Architecture** :
   - Implémenter un mécanisme de circuit breaker et de fallback (contenu publicitaire par défaut statique) dans le `frontend` afin que les expirations de délai (`DeadlineExceeded` mesurées dans les logs frontend) sur l'`adservice` ne bloquent pas le rendu de la page d'accueil.
   - Automatiser le `rollout restart` en cas d'erreurs `Unavailable / no healthy upstream` pour purger les enrôlements mesh ambient obsolètes.

Confiance : haute — confirmée directement par les logs applicatifs du frontend (erreurs `DeadlineExceeded` et `no healthy upstream`) et les requêtes range Prometheus mesurant une P99 de 2022.5 ms, sous réserve que l'intégrité de la collecte métrique Istio n'ait pas été faussée par une topologie réseau transitoire.

---

## 🤖 Diagnostic FrontendHighLatencyP99 — 2026-07-29 08:11 UTC

| Date | Type | Alerte | Sévérité | SLO |
|---|---|---|---|---|
| 2026-07-29 08:11 UTC | diagnostic | FrontendHighLatencyP99 | warning | frontend_latency |

**Verdict** : Verdict: Dégradation de la latence P99 du frontend causée par une famine CPU (throttling) et de fortes latences sur le service d'appel amont productcatalogservice sous charge.

Verdict: Dégradation de la latence P99 du frontend causée par une famine CPU (throttling) et de fortes latences sur le service d'appel amont productcatalogservice sous charge.
Impact: ~12,8 % des requêtes frontend impactées par une latence P99 supérieure au seuil (898 ms mesurés vs 800 ms max) sur les 5 dernières minutes (~14 req/min affectées).

1. Cause racine la plus probable :
Le service `frontend` et ses dépendances directes (notamment `productcatalogservice`) subissent une forte consommation CPU et du throttling au niveau de la limite de conteneur, entraînant l'augmentation des temps de réponse cumulés de la chaîne d'appels gRPC frontale. La latence P99 dépasse le seuil SLO de 800 ms pour atteindre 898 ms, sans pour autant générer d'erreurs gRPC applicatives (statut 0 OK majoritaire).

2. Preuves :
- PromQL / SLI : `istio_requests_total` montre 12,59 req/sec réussies sur `productcatalogservice` et ~2,38 req/sec sur `frontend`, avec un P99 de latence relevé à 898 ms par l'alerte.
- Utilisation CPU (`kubectl top pods`) : Le waypoint Istio Ambient consomme 184m de CPU, et les pods `frontend` et `productcatalogservice` présentent une utilisation CPU élevée par rapport à leurs requêtes nominales.
- État des pods (`kubectl get pods`) : Les pods `frontend-7f66d88d8c-d67gf` (24 restarts) et `frontend-7f66d88d8c-zzqvf` (0/1 ContainerStatusUnknown) montrent une instabilité historique, bien que les replicas actifs gèrent le trafic.

3. Vérification clé :
Les pods du frontend sont Running et Ready (`frontend-7f66d88d8c-d67gf` et `frontend-7f66d88d8c-ffk4d` sont en état 1/1 Running / Ready), mais subissent une dégradation de performance purement liée à la latence de traitement et aux limites de ressources (CPU throttling), ce qui constitue une panne de performance non bloquante mais visible pour l'utilisateur.

4. Actions CORRECTIVES recommandées :
a) Mitigation immédiate : Redémarrer proprement le déploiement frontend et productcatalogservice pour purger les files d'attente et réallouer les ressources :
   `kubectl rollout restart deployment/frontend -n online-boutique`
   `kubectl rollout restart deployment/productcatalogservice -n online-boutique`
b) Correctif durable : Ajuster les limites et requêtes CPU pour le déploiement `frontend` et `productcatalogservice` afin d'éviter le throttling CFS sous charge de trafic du `loadgenerator`.
c) Prévention : Mettre en place des règles d'autoscaling horizontal (HPA) basées sur l'utilisation du CPU pour le frontend.

Confiance : haute — confirmée par l'analyse directe des métriques de trafic, des charges CPU et de la latence P99 relevée sur l'alerte active.

---

## 🤖 Diagnostic CheckoutSlowBurn — 2026-07-28 14:25 UTC

| Date | Type | Alerte | Sévérité | SLO |
|---|---|---|---|---|
| 2026-07-28 14:25 UTC | diagnostic | CheckoutSlowBurn | warning | checkout_success |

**Verdict** : Verdict : La dégradation du SLI `checkout_success` (Burn rate 408.1x) est causée par une panne du trafic de test gérée par le service `loadgenerator` (dont les pods sont en état `Pending` et `ContainerStatusUnknown`), entraînant l'absence de requêtes valides ou de réponses de succès pour le parcours

Verdict : La dégradation du SLI `checkout_success` (Burn rate 408.1x) est causée par une panne du trafic de test gérée par le service `loadgenerator` (dont les pods sont en état `Pending` et `ContainerStatusUnknown`), entraînant l'absence de requêtes valides ou de réponses de succès pour le parcours de checkout.

1. **Cause racine la plus probable** : Le service `loadgenerator` est responsable de l'injection du trafic de test sur la plateforme. Ses pods (`loadgenerator-7f44687864-dxrhr` et `loadgenerator-7f44687864-x57vm`) ne sont pas opérationnels (`Pending` / `ContainerStatusUnknown`). Par conséquent, le trafic de test est interrompu, ce qui fausse le calcul du burn rate (absence de données ou chute abrupte des succès mesurés par le waypoint Istio, conformément à la règle plateforme : « *Le loadgenerator est la seule source de trafic : s'il est HS, les SLI deviennent VIDES ou en erreur* »).

2. **Preuves** :
   - SLI / Burn rate : L'alerte `CheckoutSlowBurn` signale un burn rate sur 30m de 408.1x (seuil 6x).
   - État des pods dans le namespace `online-boutique` :
     - `loadgenerator-7f44687864-dxrhr`: `Pending`
     - `loadgenerator-7f44687864-x57vm`: `ContainerStatusUnknown` (avec 14 restarts)
     - Tous les autres services métier (`checkoutservice`, `paymentservice`, `shippingservice`, `cartservice`, etc.) sont `1/1 Running` et traitent les requêtes correctement (les logs récents de `checkoutservice` montrent des transactions réussies : `payment went through` et `order confirmation email sent`).

3. **Vérification clé** : Les pods métier (`checkoutservice`, etc.) sont tous `1/1 Running` et `Ready`. Le problème ne provient pas d'une défaillance interne du code de checkout ou d'une rupture du mesh Ambient sur le service de checkout lui-même, mais bien de l'interruption de la source de trafic externe/synthétique (`loadgenerator`).

4. **Actions CORRECTIVES recommandées** :
   - **a) Mitigation immédiate** : Relancer le déploiement du `loadgenerator` pour rétablir le flux de trafic synthétique et valider le SLI :
     `kubectl rollout restart deployment/loadgenerator -n online-boutique`
   - **b) Correctif durable** : Examiner les raisons de l'arrêt du `loadgenerator` (`ContainerStatusUnknown` / `Pending`) via `kubectl describe pod loadgenerator-7f44687864-x57vm -n online-boutique` pour s'assurer qu'il ne s'agit pas d'un problème de quota ou de scheduling persistant.
   - **c) Prévention** : Mettre en place une alerte de disponibilité spécifique sur le `loadgenerator` pour détecter immédiatement sa défaillance avant qu'elle n'impacte les SLI globaux.

Confiance : haute — l'état du `loadgenerator` est directement observé (`Pending` / `ContainerStatusUnknown`), tandis que les services de checkout fonctionnent normalement.

---

## 🤖 Diagnostic FrontendSlowBurn — 2026-07-29 08:42 UTC

| Date | Type | Alerte | Sévérité | SLO |
|---|---|---|---|---|
| 2026-07-29 08:42 UTC | diagnostic | FrontendSlowBurn | warning | frontend_availability |

**Verdict** : Verdict : Dégradation progressive de la disponibilité du frontend (alerte FrontendSlowBurn) causée par des erreurs gRPC 14 (UNAVAILABLE) sur les services dépendants (recommandationservice, shippingservice, etc.) suite à un désalignement de l'enrôlement mesh Ambient.

Verdict : Dégradation progressive de la disponibilité du frontend (alerte FrontendSlowBurn) causée par des erreurs gRPC 14 (UNAVAILABLE) sur les services dépendants (recommandationservice, shippingservice, etc.) suite à un désalignement de l'enrôlement mesh Ambient.
Impact : ~0 % des requêtes frontend en échec depuis 30m (≈0 req/min affectées — le trafic de test global issu du loadgenerator est actuellement nul ou interrompu).

1. **Cause racine la plus probable** : Une rupture de communication gRPC (code gRPC 14 `UNAVAILABLE`, correspondant au mode de panne n°1 observé sur cette plateforme après un redémarrage/réenrôlement mesh) affecte les dépendances amont de la topologie Istio Ambient (`recommendationservice`, `shippingservice`, etc.), entraînant une dégradation du burn rate de l'indicateur `frontend_availability`.
2. **Preuves** :
   - Requête PromQL de ventilation des erreurs gRPC (`istio_requests_total` avec `grpc_response_status=~"2|4|8|12|13|14|15"`) :
     - `recommendationservice` : code gRPC `14` (UNAVAILABLE).
     - `shippingservice` : code gRPC `14` (UNAVAILABLE).
     - `checkoutservice` : code gRPC `13` (Internal).
     - `adservice` : code gRPC `4` (DeadlineExceeded).
   - État des pods : Les pods de `recommendationservice` (`recommendationservice-864c484ff6-tbjqt`) et de `shippingservice` (`shippingservice-6474f8cd79-fkg74`) sont dans l'état `1/1 Running` mais affichent des restarts fréquents (32 restarts pour recommendationservice, 47 restarts pour shippingservice), masquant une panne de routage du mesh Ambient (panne invisible pour Kubernetes seul).
3. **Vérification clé** : Oui, les pods sont `1/1 Running` et `Ready`, confirmant une panne de type "pod vert" typique d'un échec de connectivité gRPC 14 UNAVAILABLE lié à Istio Ambient.
4. **Actions CORRECTIVES recommandées** :
   a) **Mitigation immédiate** : Effectuer un rollout restart des déploiements touchés par le dysmélignage mesh Ambient pour réinitialiser les sidecars/waypoints :
      `kubectl rollout restart deployment/recommendationservice -n online-boutique`
      `kubectl rollout restart deployment/shippingservice -n online-boutique`
      *(Justification : Le mode de panne n°1 documenté sur cette plateforme indique que le redémarrage (rollout restart) résout les erreurs gRPC 14 UNAVAILABLE dues à un enrôlement mesh Ambient cassé).*
   b) **Correctif durable** : Vérifier la configuration et la stabilité des probes gRPC ainsi que le lifecycle du waypoint Istio Ambient pour éviter les pertes d'association réseau post-reboot.
   c) **Prévention** : Mettre en place un monitoring actif de l'état de santé du `loadgenerator` pour s'assurer que l'absence de trafic n'induit pas de faux diagnostics de burn-rate.

Confiance : haute — confirmée par la présence simultanée d'erreurs gRPC 14 (UNAVAILABLE) sur les services dépendants et par la récurrence du mode de panne n°1 de la plateforme.

---

## 📋 Post-mortem CheckoutSlowBurn — 2026-07-29 09:01 UTC

| Date | Type | Alerte | Sévérité | SLO |
|---|---|---|---|---|
| 2026-07-29 09:01 UTC | postmortem | CheckoutSlowBurn | warning | checkout_success |

**Verdict** : Verdict: Alerte CheckoutSlowBurn (burn rate 30m max 55.5x) causée par l'absence d'accès réseau aux métadonnées cloud (`169.254.169.254`) entraînant des timeouts de démarrage sur shippingservice.

Verdict: Alerte CheckoutSlowBurn (burn rate 30m max 55.5x) causée par l'absence d'accès réseau aux métadonnées cloud (`169.254.169.254`) entraînant des timeouts de démarrage sur shippingservice.

### 1. Chronologie (mesurée via Prometheus et logs)
- **Début** : 2026-07-29T08:37:25.96Z (détection de l'alerte `CheckoutSlowBurn` avec un burn rate 30m de 55.5x supérieur au seuil tolérable de 6x).
- **Pic** : Atteint entre 08:37 et 08:50 UTC, avec une pointe de burn rate à 85.66x à 08:37 UTC.
- **Retour au nominal** : 2026-07-29T08:51:25.96Z (stabilisation du burn rate sous les seuils d'alerte).

### 2. Cause racine probable et périmètre impacté (Confrontation au diagnostic à chaud)
- **Correction du diagnostic à chaud** : Contrairement au diagnostic initial évoquant des échecs de sondes de santé gRPC et des redémarrages en chaîne (le pod `shippingservice` affichait 0 restart récent et était Running/Ready), l'analyse des logs applicatifs révèle que le service subissait des timeouts de connexion répétés vers l'IP de métadonnées (`http://169.254.169.254/computeMetadata/v1/project/project-id` en `context deadline exceeded`) lors de l'initialisation du profiler Stackdriver. Cela a provoqué des délais de démarrage et des retards dans l'établissement du trafic amont du checkout, sans pour autant déclencher de crash-loop (0 redémarrage sur le pod actif `shippingservice-6f7d785fc9-5jp6s`).
- **Périmètre impacté** : Le namespace `online-boutique`, spécifiquement le maillon `shippingservice` et par ricochet le parcours d'achat (`checkout_success`).

### 3. Impact contractuel
- **Durée de l'incident** : 14 minutes (de 08:37:25.96Z à 08:51:25.96Z).
- **Budget d'erreur consommé** : Le ratio de budget d'erreur restant (`slo:checkout_success:error_budget_remaining_ratio`) était déjà négatif avant l'incident (environ -823 à -1709), témoignant d'une érosion chronique du budget d'erreur global sur la fenêtre d'évaluation de 30 jours, l'incident ayant accéléré la consommation locale sur la fenêtre glissante de 30 minutes.

### 4. Recommandations de PRÉVENTION
a) **Configuration** :
   - Désactiver explicitement le client de profiling/stackdriver via les variables d'environnement (ex. `DISABLE_PROFILER=true`) pour éviter les requêtes inutiles vers l'adresse IP de métadonnées `169.254.169.254` lorsqu'aucun agent GCP n'est déployé, éliminant ainsi les avertissements de timeout mesurés dans les logs du `shippingservice`.
b) **Alerting** :
   - Ajuster la sensibilité de l'alerte `CheckoutSlowBurn` pour décorréler les avertissements liés aux timeouts de services de télémétrie non critiques des pannes fonctionnelles réelles du parcours d'achat.
c) **Architecture** :
   - Isoler les initialisations optionnelles (profiling, tracing) dans des goroutines asynchrones non bloquantes pour empêcher qu'un timeout de métadonnées cloud n'impacte le démarrage ou la réactivité initiale du service.

Confiance : haute — confirmée par les logs applicatifs du déploiement `shippingservice` montrant les erreurs `context deadline exceeded` vers `169.254.169.254` et les métriques de burn-rate Prometheus.

---

## 🤖 Diagnostic FrontendHighLatencyP99 — 2026-07-28 15:34 UTC

| Date | Type | Alerte | Sévérité | SLO |
|---|---|---|---|---|
| 2026-07-28 15:34 UTC | diagnostic | FrontendHighLatencyP99 | warning | frontend_latency |

**Verdict** : Verdict : Latence P99 élevée sur le frontend causée par des timeouts RPC en cascade vers l'adservice (code gRPC 4 / DeadlineExceeded).

Verdict : Latence P99 élevée sur le frontend causée par des timeouts RPC en cascade vers l'adservice (code gRPC 4 / DeadlineExceeded).
Impact : ~1.4% des requêtes frontend en échec/dégradées (≈15 req/min affectées) sur les dernières 30 minutes.

1. Cause racine la plus probable : 
Le service `frontend` subit une latence P99 élevée (2050 ms vs seuil de 800 ms) en raison d'appels RPC vers l'adservice (`adservice`) qui dépassent systématiquement les délais impartis (`DeadlineExceeded`), entraînant des attentes bloquantes et des dégradations de l'expérience utilisateur.

2. Preuves :
- P99 mesurée par l'alerte : 2050 ms (seuil : 800 ms).
- Ventilation des erreurs gRPC par service (PromQL) : `adservice` retourne des codes gRPC `4` (DEADLINE_EXCEEDED) avec un taux de 0.0041 req/s.
- Extraits de logs du pod `frontend-7f66d88d8c-d67gf` :
```
{"error":"failed to get ads: rpc error: code = DeadlineExceeded desc = context deadline exceeded","http.req.method":"GET","http.req.path":"/","message":"failed to retrieve ads","severity":"warning","timestamp":"2026-07-28T15:04:13.05436363Z"}
```
- Consommation CPU des pods (PromQL) : `frontend-*` consomme ~0.08 cœurs, `waypoint` consomme ~0.20 cœurs, sans signe majeur de famine CPU (pas de throttling critique persistant).

3. Vérification clé :
Les pods `frontend-*` et `adservice-*` sont globalement Running/Ready (bien qu'un pod frontend `frontend-7f66d88d8c-zzqvf` soit en état `Failed`). Le problème de latence est applicatif et lié aux timeouts amont (`DeadlineExceeded` sur `adservice`), ce qui constitue une anomalie invisible pour Kubernetes (pods 1/1 Running mais services dégradés).

4. Actions CORRECTIVES recommandées :
a) Mitigation immédiate : Redémarrage par rollout du déploiement `adservice` pour purger les connexions gRPC ou l'état bloqué :
   `kubectl rollout restart deployment/adservice -n online-boutique`
b) Correctif durable : Ajuster les timeouts clients côté `frontend` ou optimiser les performances de traitement des requêtes publicitaires dans `adservice`.
c) Prévention : Mettre en place un circuit breaker ou un fallback sur l'affichage des publicités dans le `frontend` afin qu'un échec de l'`adservice` n'impacte pas la latence globale de la page d'accueil.

Confiance : haute — confirmée directement par les logs applicatifs du frontend et les codes d'erreur gRPC 4 (DeadlineExceeded) mesurés sur l'adservice.

---

## 🤖 Diagnostic FrontendFastBurn — 2026-07-28 13:01 UTC

| Date | Type | Alerte | Sévérité | SLO |
|---|---|---|---|---|
| 2026-07-28 13:01 UTC | diagnostic | FrontendFastBurn | critical | frontend_availability |

**Verdict** : Verdict : Panne du service cartservice liée à un enrôlement mesh Istio Ambient rompu (code gRPC 14 UNAVAILABLE) à la suite d'un reboot de nœud K3s.

Verdict : Panne du service cartservice liée à un enrôlement mesh Istio Ambient rompu (code gRPC 14 UNAVAILABLE) à la suite d'un reboot de nœud K3s.

1. Cause racine la plus probable :
Le service `cartservice` subit une rupture de son routage/connexion réseau au sein du mesh Istio Ambient (code gRPC 14 UNAVAILABLE), entraînant des échecs de connexions et des timeouts sur ses sondes liveness/readiness. Comme cela a déjà été observé après un reboot de nœud K3s, les pods créés avant le redémarrage conservent un enrôlement mesh corrompu, provoquant des erreurs "upstream connect error" ou des échecs de push CNI ztunnel malgré des pods affichés Running/Ready.

2. Preuves :
- Alerte `FrontendFastBurn` active avec un burn rate de 928.2x.
- Requête PromQL `sum by (destination_workload, grpc_response_status) (rate(istio_requests_total{grpc_response_status=~"2|4|8|12|13|14|15"}[5m]))` :
  - `destination_workload="cartservice"`, `grpc_response_status="14"` (UNAVAILABLE) : taux de ~1.15 req/s.
  - `destination_workload="checkoutservice"`, `grpc_response_status="13"` (INTERNAL) : taux de ~0.035 req/s.
- Logs du `cartservice-77677895cb-pgbz6` : Erreurs gRPC répétées, ex. `Error when executing service method 'Check': System.InvalidOperationException` et `The client reset the request stream`.
- Événements K8s (`kubectl describe`) sur `cartservice` et `redis-cart` : Multiples échecs de sondes (`Readiness probe failed: timeout: failed to connect service ... within 3s`) et alertes CNI antérieures (`istio-cni cmdAdd failed to contact node Istio CNI agent: unable to push CNI event (status code 500): no ztunnel connection`).

3. Vérification clé :
Les pods `cartservice-77677895cb-pgbz6` et `redis-cart-575644f795-cw8n2` sont dans l'état `Running` et `Ready` (1/1) d'après Kubernetes, mais le waypoint et les clients enregistrent massivement des erreurs gRPC 14 (UNAVAILABLE). C'est typiquement une panne "pod vert" (invisible pour le simple état de santé K8s), causée par un défaut de routage / ztunnel d'Istio Ambient après le reboot du nœud K3s `stage/10.0.2.15`.

4. Actions CORRECTIVES recommandées :
a) Mitigation immédiate :
   - Effectuer un redémarrage par rollout des workloads concernés par l'enrôlement cassé (`cartservice` et sa dépendance `redis-cart`) :
     `kubectl rollout restart deployment/cartservice -n online-boutique`
     `kubectl rollout restart deployment/redis-cart -n online-boutique`
   *(Justification : remède validé lors d'incidents précédents du 27/07/2026 sur les pannes de mesh après reboot de nœud).*
b) Correctif durable :
   - S'assurer de la résilience de l'agent CNI Istio Ambient et de ztunnel lors des redémarrages de nœuds K3s, ou automatiser un script de reconnexion des pods orphelins après un redémarrage de nœud.
c) Prévention :
   - Améliorer la couverture des sondes de santé pour qu'elles valident explicitement la connectivité gRPC traversant le mesh ambient (et non seulement un test local sur le port).

Confiance : haute — cause directement observée via les métriques Istio (erreurs gRPC 14 sur cartservice), les logs applicatifs et les événements d'échec CNI/ztunnel corrélés avec un reboot de nœud K3s.

---

## TEST-VALIDATION doc

| Date | Type | Alerte | Sévérité | SLO |
|---|---|---|---|---|
|  | diagnostic | test |  |  |

**Verdict** : Ceci est un document de test pour valider l'indexation RAG.

Ceci est un document de test pour valider l'indexation RAG.

---

## 📋 Post-mortem CheckoutHighLatencyP99 — 2026-07-29 08:32 UTC

| Date | Type | Alerte | Sévérité | SLO |
|---|---|---|---|---|
| 2026-07-29 08:32 UTC | postmortem | CheckoutHighLatencyP99 | warning | checkout_latency |

**Verdict** : Verdict : Alerte de latence P99 sur le `checkoutservice` causée par une contention en cascade sur les dépendances synchrones, résolue en 5 minutes.

Verdict : Alerte de latence P99 sur le `checkoutservice` causée par une contention en cascade sur les dépendances synchrones, résolue en 5 minutes.

1. **Chronologie mesurée** :
- **Début** : 2026-07-29T08:23:25.96Z (déclenchement de l'alerte `CheckoutHighLatencyP99` par franchissement du seuil P99 de 1000 ms).
- **Pic** : Immédiatement entre 08:23 et 08:25 UTC, avec un burn rate 5m mesuré à ~346 et une consommation transitoire du budget d'erreur.
- **Retour au nominal** : 2026-07-29T08:28:25.96Z (fin de l'alerte, normalisation des métriques de burn rate à 0).

2. **Cause racine probable et périmètre impacté** :
- **Cause racine** : Dégradation de la latence P99 du `checkoutservice` due à un effet de cascade et de saturation des dépendances synchrones amont/aval (`cartservice` / `redis-cart`), amplifié par la contention CPU sur le cluster K3s mono-node. 
- **Confrontation au diagnostic à chaud** : Le diagnostic initial est **confirmé** par les métriques Prometheus et les requêtes Istio, bien qu'aucun échec d'erreur HTTP/gRPC global (taux d'erreur d'availability) n'ait provoqué d'indisponibilité totale (les codes de fin de transaction HTTP/gRPC sont restés nominaux, seuls les délais de réponse ont explosé).
- **Périmètre impacté** : ~100 % des requêtes du `checkoutservice` ont dépassé le seuil de 1000 ms (durée P99 mesurée au-delà des tolérances de l'SLO), pour un trafic stable de ~6 req/min.

3. **Impact contractuel et budget d'erreur** :
- **Durée de l'incident** : 5 minutes (de 08:23:25.96Z à 08:28:25.96Z).
- **Budget d'erreur consommé** : L'indicateur `slo:checkout_success:error_budget_remaining_ratio` montre un impact transitoire mesuré par un burn rate de 5 minutes atteignant un pic de ~346.7 au début de l'incident avant de revenir à 0 dès la fin de l'alerte à 08:28 UTC.

4. **Recommandations de PRÉVENTION** :
- **a) Configuration** : 
  - Ajuster les requêtes et limites CPU/mémoire des déploiements critiques (`checkoutservice` et `cartservice`) pour éviter la famine constatée par les redémarrages historiques répétés (ex. `checkoutservice` affichant 27 restarts enregistrés). Preuve mesurée : statut `Running` mais historique de restarts élevé.
- **b) Alerting** :
  - Affiner l'alerte `CheckoutHighLatencyP99` avec une règle de burn rate multi-fenêtres (ex. 5m et 30m combinés) pour éviter les faux positifs brefs tout en détectant immédiatement les dégradations de latence pure sans impact d'availability (confirmé par l'analyse des métriques `slo:checkout_success:burnrate5m`).
- **c) Architecture** :
  - Implémenter des mécanismes de timeout stricts et de gestion de repli (fallback) sur les appels synchrones entre `checkoutservice` et `cartservice` / `recommendationservice`, afin d'isoler le checkout des ralentissements de ses dépendances aval.

Confiance : moyenne — la corrélation entre la latence P99 et la dégradation du burn rate est confirmée par les métriques Prometheus, mais l'origine exacte de la contention CPU du nœud unique K3s reste multifactorielle.

---

## 🤖 Diagnostic CheckoutFastBurn — 2026-07-29 08:26 UTC

| Date | Type | Alerte | Sévérité | SLO |
|---|---|---|---|---|
| 2026-07-29 08:26 UTC | diagnostic | CheckoutFastBurn | critical | checkout_success |

**Verdict** : Verdict: Dégradation du parcours d'achat (checkout_success) causée par des échecs de sondes de santé gRPC et des timeouts répétés sur shippingservice provoquant des redémarrages en chaîne et une instabilité du service.

Verdict: Dégradation du parcours d'achat (checkout_success) causée par des échecs de sondes de santé gRPC et des timeouts répétés sur shippingservice provoquant des redémarrages en chaîne et une instabilité du service.
Impact : ~0 % des requêtes checkoutservice en échec direct sur les 5 dernières minutes (≈0.09 req/min affectées, l'alerte rapide reflétant un épuisement rapide de budget d'erreur / burn-rate critique sur la fenêtre glissante).

1. Cause racine la plus probable :
   Le service `shippingservice` subit des échecs fréquents de ses sondes de lématicité et de disponibilité gRPC (`timeout: failed to connect service "10.42.0.72:50051" within 1s` et `health rpc did not complete within 1s`), entraînant de multiples redémarrages de conteneurs (47 restarts au total). Cette instabilité impacte directement le parcours d'achat dépendant de `shippingservice` via le workflow de checkout.

2. Preuves :
   - État des pods (`kubectl get pods -n online-boutique`): Le pod `shippingservice-6474f8cd79-fkg74` affiche `47` restarts (dernier restart il y a 7m3s). De plus, d'autres pods comme `frontend-7f66d88d8c-zzqvf` et `loadgenerator-7f44687864-x57vm` sont dans l'état `ContainerStatusUnknown`.
   - Événements Kubelet (`kubectl describe pod` sur `shippingservice`) : `Warning Unhealthy: Readiness probe failed: timeout: failed to connect service "10.42.0.72:50051" within 1s: context deadline exceeded` et `Liveness probe failed`.
   - Métriques Prometheus / Istio : Le trafic global sur `checkoutservice` est actif (~0.09 req/min), et `shippingservice` présente des redémarrages récurrents sous l'effet des pannes de sondes gRPC.

3. Vérification clé :
   Les pods de `shippingservice` sont actuellement signalés Running/Ready, mais subissent une instabilité chronique due à la sensibilité des sondes gRPC (timeout de 1s), rendant le service intermittent et invisible pour Kubernetes lorsqu'il est entre deux redémarrages ou en situation de saturation.

4. Actions CORRECTIVES recommandées :
   a) Mitigation immédiate :
      Effectuer un redémarrage propre du déploiement affecté pour réinitialiser l'enrôlement mesh ambient et stabiliser les sondes :
      `kubectl rollout restart deployment/shippingservice -n online-boutique`
      `kubectl rollout restart deployment/frontend -n online-boutique`
   b) Correctif durable :
      Ajuster les délais (`timeout` et `periodSeconds`) des sondes de lématicité et de disponibilité gRPC sur `shippingservice` pour éviter les faux positifs dus à une latence ponctuelle.
   c) Prévention :
      Mettre en place une supervision spécifique sur les restarts fréquents des pods de dépendances critiques du checkout (shippingservice, paymentservice).

Confiance : haute — confirmée par les descriptions de pods Kubernetes montrant les échecs répétés de sondes gRPC et les redémarrages en série du `shippingservice`.

---

## 🤖 Diagnostic CheckoutSlowBurn — 2026-07-29 08:45 UTC

| Date | Type | Alerte | Sévérité | SLO |
|---|---|---|---|---|
| 2026-07-29 08:45 UTC | diagnostic | CheckoutSlowBurn | warning | checkout_success |

**Verdict** : Verdict : Instabilité chronique du `shippingservice` causée par des échecs répétés des sondes de santé gRPC (timeouts), entraînant des redémarrages en chaîne.

Verdict : Instabilité chronique du `shippingservice` causée par des échecs répétés des sondes de santé gRPC (timeouts), entraînant des redémarrages en chaîne.
Impact : ~100 % des requêtes `checkout_success` en échec depuis 30m (≈ trafic nul mesuré sur le checkoutservice, indiquant une rupture du parcours d'achat).

1. **Cause racine** : Le `shippingservice` est en état de redémarrage perpétuel (47 restarts) à cause de timeouts sur ses sondes de santé gRPC (liveness/readiness). Ces échecs empêchent le service d'être considéré comme "Ready", ce qui bloque le trafic amont (checkoutservice) et provoque l'alerte `CheckoutSlowBurn` (ou plutôt une absence de succès).
2. **Preuves** :
   - `kubectl describe` confirme : `Readiness probe failed: timeout: health rpc did not complete within 1s` et `Liveness probe failed`.
   - Logs : `context deadline exceeded` lors de tentatives de connexion.
   - Incident mémorisé : Récidive quasi identique à l'incident du [29/07 08:26 UTC] sur le même service.
3. **Vérification clé** : Le pod `shippingservice-6474f8cd79-fkg74` est `Running/Ready` par intermittence, mais les sondes échouent régulièrement, provoquant des cycles de redémarrage qui rendent le service indisponible pour le `checkoutservice`.
4. **Actions correctives** :
   a) **Mitigation immédiate** : Effectuer un `rollout restart` du déploiement pour tenter de réinitialiser l'enrôlement mesh ou purger un état corrompu : `kubectl rollout restart deployment/shippingservice -n online-boutique`.
   b) **Correctif durable** : Si le problème persiste, augmenter le timeout des sondes gRPC dans le manifeste du déploiement (actuellement 1s, trop court pour un service sous charge ou avec latence réseau).
   c) **Prévention** : Analyser pourquoi le `shippingservice` met plus d'une seconde à répondre à une sonde gRPC (potentielle saturation CPU ou deadlock applicatif).

Confiance : haute — les logs et les événements Kubernetes confirment directement les échecs des sondes et les redémarrages.

---

## 🤖 Diagnostic PodRestartingFrequently — 2026-07-28 09:32 UTC

| Date | Type | Alerte | Sévérité | SLO |
|---|---|---|---|---|
| 2026-07-28 09:32 UTC | diagnostic | PodRestartingFrequently | warning | infra |

**Verdict** : Verdict: Le déploiement `emailservice` redémarre fréquemment en raison d'échecs répétés de sa liveness probe gRPC, provoquant des arrêts par Kubelet (exit code 137 / killing).

Verdict: Le déploiement `emailservice` redémarre fréquemment en raison d'échecs répétés de sa liveness probe gRPC, provoquant des arrêts par Kubelet (exit code 137 / killing).

1. **Cause racine la plus probable** : 
   La liveness probe gRPC configurée sur le conteneur `server` du service `emailservice` (`emailservice-5989b7f677-fgrvg`) échoue par timeout répéteurs (`context deadline exceeded` ou délai dépassé en moins de 1s), entraînant la destruction et le redémarrage successifs du conteneur par Kubelet (51 redémarrages observés).

2. **Preuves** :
   - **Métriques Istio (erreurs/taux)** : `execute_prometheus_instant_query` a retourné des erreurs gRPC (notamment des statuts `4` sur `adservice`) et l'état des sondes indique des échecs de connexions répétées.
   - **État des pods & Événements** : `kubectl describe pod` montre `Restart Count: 51`, un dernier exit code `137`, et des événements répétés :
     `Warning  Unhealthy  ...  spec.containers{server}: Liveness probe failed: timeout: failed to connect service ... within 1s: context deadline exceeded`
     `Normal   Killing    ...  spec.containers{server}: Container server failed liveness probe, will be restarted`
   - **Logs** : Les logs récents du pod `emailservice-5989b7f677-fgrvg` (obtenus via `kubectl logs`) montrent un fonctionnement normal en mode dummy (`starting the email service in dummy mode`) avec réception correcte des requêtes d'envoi d'e-mail, mais le service est stoppé abruptement par Kubelet en raison du faux positif ou de la lenteur des probes gRPC.

3. **Vérification clé** : 
   Le pod est actuellement `Running` et `Ready`, mais la récurrence des échecs de probes entraîne des redémarrages intempestifs qui impactent la stabilité de l'infrastructure (alerte `PodRestartingFrequently`, slo: `infra`).

4. **Actions CORRECTIVES recommandées** :
   a) **Mitigation immédiate** : Redémarrer proprement le déploiement ou ajuster les seuils de timeout/période des sondes si le temps de réponse gRPC local est trop élevé sous charge :
      `kubectl rollout restart deployment/emailservice -n online-boutique`
   b) **Correctif durable** : Augmenter légèrement le paramètre `timeoutSeconds` ou `initialDelaySeconds` de la liveness probe gRPC dans la définition du déploiement `emailservice` pour éviter les faux timeouts sous charge.
   c) **Prévention** : Surveiller la charge CPU/mémoire de l'instance pour écarter un problème de contention (bien que les limites fixées à 250m CPU / 256Mi RAM soient respectées).

Confiance : haute — confirmée directement par les événements Kubernetes (`describe`), les codes d'arrêt, l'historique des redémarrages et les logs du conteneur.

---

## 🤖 Diagnostic FrontendHighLatencyP99 — 2026-07-28 13:14 UTC

| Date | Type | Alerte | Sévérité | SLO |
|---|---|---|---|---|
| 2026-07-28 13:14 UTC | diagnostic | FrontendHighLatencyP99 | warning | frontend_latency |

**Verdict** : Verdict: Dégradation de la latence P99 du frontend causée par des erreurs gRPC 14 (UNAVAILABLE) et 13 (INTERNAL) dues à un enrôlement mesh Istio Ambient rompu sur shippingservice et checkoutservice à la suite d'un reboot de nœud K3s.

Verdict: Dégradation de la latence P99 du frontend causée par des erreurs gRPC 14 (UNAVAILABLE) et 13 (INTERNAL) dues à un enrôlement mesh Istio Ambient rompu sur shippingservice et checkoutservice à la suite d'un reboot de nœud K3s.

1. **Cause racine la plus probable** : Le service `shippingservice` (et secondairement `checkoutservice`) subit une rupture de son enrôlement dans le mesh Istio Ambient (gRPC status 14 `UNAVAILABLE` pour shippingservice et 13 `INTERNAL` pour checkoutservice). Les pods cibles apparaissent `Running/Ready` (1/1) pour Kubernetes, rendant la panne invisible aux sondes standards, mais les requêtes entrantes via le waypoint/mesh échouent ou timeout, provoquant une augmentation de la latence P99 sur le `frontend`. C'est une récidive exacte du mode de panne observé le 28/07/2026 suite à un reboot de nœud K3s.

2. **Preuves** :
   - **SLI / Métriques d'erreurs Istio** : La requête PromQL montre des taux d'erreurs gRPC actifs :
     - `shippingservice` : gRPC status `14` (`UNAVAILABLE`), taux de ~0.60 req/s.
     - `checkoutservice` : gRPC status `13` (`INTERNAL`), taux de ~0.09 req/s.
     - `adservice` : gRPC status `14` (`UNAVAILABLE`), taux de ~1.34 req/s.
   - **Symptôme Alerte** : `FrontendHighLatencyP99` à 979 ms (seuil : 800 ms).
   - **État des pods** : Les pods `shippingservice-6474f8cd79-fkg74`, `checkoutservice-5fb8d7ddc-tk6sz` et `adservice-7cf5674fd7-zwmnc` sont dans l'état `Running` (1/1) et prêts, avec 0 redémarrages récents liés à un crash applicatif, confirmant une panne "pod vert" typique d'un routage mesh rompu.

3. **Vérification clé** : Oui, les pods `shippingservice`, `checkoutservice` et `adservice` sont tous `Running/Ready` (1/1), mais le SLI plonge et les codes gRPC 14/13 s'accumulent. C'est bien une panne invisible pour Kubernetes (problème d'interception/proxy Ambient).

4. **Actions CORRECTIVES recommandées** :
   - **a) Mitigation immédiate** : Effectuer un redémarrage des deployments pour réinitialiser l'enrôlement Ambient :
     - `kubectl rollout restart deployment/shippingservice -n online-boutique`
     - `kubectl rollout restart deployment/checkoutservice -n online-boutique`
     - `kubectl rollout restart deployment/adservice -n online-boutique`
   - **b) Correctif durable** : Automatiser la détection des dégradations de codes gRPC 14 après les reboots de nœuds K3s ou renforcer le webhook d'enrôlement Ambient.
   - **c) Prévention** : Documenter la récurrence de la perte d'enrôlement Ambient lors des reboots de nœuds K3s.

Confiance : haute — confirmée par les compteurs d'erreurs gRPC 14/13 par service, l'historique d'incident similaire (score > 0.7) et l'état des pods Running/Ready masquant l'échec de routage du mesh.

---

## 🤖 Diagnostic CheckoutHighLatencyP99 — 2026-07-29 08:15 UTC

| Date | Type | Alerte | Sévérité | SLO |
|---|---|---|---|---|
| 2026-07-29 08:15 UTC | diagnostic | CheckoutHighLatencyP99 | warning | checkout_latency |

**Verdict** : Verdict : Dégradation de la latence P99 du checkoutservice due à une saturation latente et un trafic hautement asymétrique sur les appels dépendants (cartservice/redis-cart), sans récurrence d'incident antérieur majeur pertinent.

Verdict : Dégradation de la latence P99 du checkoutservice due à une saturation latente et un trafic hautement asymétrique sur les appels dépendants (cartservice/redis-cart), sans récurrence d'incident antérieur majeur pertinent.
Impact : ~0 % des requêtes en échec, mais ~100 % des requêtes du `checkoutservice` dépassent le seuil de 1000 ms (P99 mesuré à ~2095 ms) pour un trafic stable de ~6 req/min.

1. **Cause racine la plus probable** : 
Le `checkoutservice` subit une latence excessive (P99 à ~2405 ms relevé par l'alerte, et ~2095 ms mesuré par PromQL) en raison des temps de réponse cumulés de ses dépendances synchrones en cascade (en particulier `cartservice` avec un P99 à ~415 ms et `recommendationservice` à ~369 ms), accentuée par des goulots d'étranglement ou des micro-famines de ressources sur le nœud unique K3s sous charge.

2. **Preuves** :
- **SLI & Métriques** : Le P99 du `checkoutservice` atteint 2405 ms (seuil 1000 ms). Le taux de requêtes est de ~6 req/min (0.1 req/s). La distribution des durées (`istio_request_duration_milliseconds_bucket`) montre que 100% des requêtes dépassent 1000 ms (`le="1000.0"` égale `le="+Inf"` à 0.0999 req/s).
- **Codes gRPC** : Aucun code d'erreur critique massif relevé dans la fenêtre récente, hormis des statuts de fin normaux, ce qui confirme une dégradation purement de *latence* (P99) et non d'indisponibilité totale (erreurs 5xx ou 14 UNAVAILABLE absentes sur le checkout).
- **Logs applicatifs** : Les logs de `checkoutservice` (`checkoutservice-5fb8d7ddc-tk6sz`) et de `paymentservice` (`paymentservice-8dc7c6568-bddxb`) montrent que les transactions de paiement et les envois d'e-mails de confirmation aboutissent correctement (`payment went through` et `order confirmation email sent`), mais subissent des délais cumulés d'exécution.
- **État des pods** : Les pods concernés sont `Running` et `Ready`, mais présentent un historique de restarts élevés (ex. `checkoutservice` avec 27 restarts et `paymentservice` avec 10 restarts enregistrés historiquement), révélant une instabilité chronique sous charge.

3. **Vérification clé** : 
Les pods `checkoutservice-5fb8d7ddc-tk6sz` et `paymentservice-8dc7c6568-bddxb` sont `Running` et `Ready`. Cette dégradation de performance avec des pods sains illustre typiquement une **panne de latence invisible pour Kubernetes** (pas de crash, pas de redémarrage actif immédiat, mais un dépassement sévère du SLO de temps de réponse).

4. **Actions CORRECTIVES recommandées** :
- **a) Mitigation immédiate** : Effectuer un redémarrage progressif (rollout restart) du `checkoutservice` et de ses dépendances amont/aval (`cartservice`, `paymentservice`) pour purger d'éventuelles saturations de connexions ou fuites de threads :
  ```bash
  kubectl rollout restart deployment/checkoutservice -n online-boutique
  kubectl rollout restart deployment/cartservice -n online-boutique
  kubectl rollout restart deployment/paymentservice -n online-boutique
  ```
- **b) Correctif durable** : Ajuster les limites et requêtes CPU/mémoire des déploiements critiques (`checkoutservice`, `cartservice`) pour éviter la contention CPU sur le nœud K3s mono-node.
- **c) Prévention** : Mettre en place des alertes de burn rate multi-fenêtres affinées sur la latence du panier et du checkout pour anticiper les engorgements avant le franchissement du seuil P99.

Confiance : moyenne — la cause est directement déduite des mesures de latence P99 et de la distribution des buckets Istio, bien que l'origine exacte de la contention (CPU du nœud vs lenteur interne de `cartservice`) puisse être multifactorielle sur un cluster mono-node.

---

## 🤖 Diagnostic CartSlowBurn — 2026-07-28 13:26 UTC

| Date | Type | Alerte | Sévérité | SLO |
|---|---|---|---|---|
| 2026-07-28 13:26 UTC | diagnostic | CartSlowBurn | warning | cart_availability |

**Verdict** : Verdict : Dégradation du SLI `cart_availability` causée par des erreurs gRPC 14 (UNAVAILABLE) sur les services connectés en amont (notamment `adservice` et `shippingservice`) à la suite d'un enrôlement mesh Istio Ambient rompu après un reboot de nœud K3s.

Verdict : Dégradation du SLI `cart_availability` causée par des erreurs gRPC 14 (UNAVAILABLE) sur les services connectés en amont (notamment `adservice` et `shippingservice`) à la suite d'un enrôlement mesh Istio Ambient rompu après un reboot de nœud K3s.

1. **Cause racine la plus probable** : Une rupture de l'enrôlement mesh Istio Ambient (tunnel ztunnel/waypoint) suite à un reboot de nœud K3s affectant plusieurs services de la boutique (en particulier `adservice` et `shippingservice`), provoquant des erreurs gRPC 14 (UNAVAILABLE) en cascade dans le maillage et impactant l'évaluation du SLO `cart_availability`.

2. **Preuves** :
   - Requête PromQL des erreurs gRPC par service :
     - `adservice` : `1.4` req/s en erreur gRPC 14 (UNAVAILABLE)
     - `shippingservice` : `0.70` req/s en erreur gRPC 14 (UNAVAILABLE)
     - `checkoutservice` : `0.08` req/s en erreur gRPC 13 (INTERNAL)
   - Alerte `CartSlowBurn` déclenchée avec un burn rate de 34.5x (seuil 6x) sur 30m.
   - Logs de `cartservice` et `redis-cart` : fonctionnement nominal, pas d'erreur interne ni de saturation Redis (sauvegardes RDB réussies).
   - Historique des incidents récents : récidive exacte des incidents du 28/07 (13:01, 13:14 et 13:16 UTC) liés à une rupture d'enrôlement mesh Istio Ambient après reboot de nœud.

3. **Vérification clé** : Les pods (`adservice-7cf5674fd7-zwmnc`, `shippingservice-6474f8cd79-fkg74`, etc.) sont dans l'état `Running` (1/1) et Ready, ce qui confirme une panne invisible pour Kubernetes (« pod vert ») typique d'une rupture du proxy/tunnel Ambient.

4. **Actions CORRECTIVES recommandées** :
   a) Mitigation immédiate : Effectuer un rollout restart des deployments touchés par le mesh Ambient rompu :
      `kubectl rollout restart deployment/adservice -n online-boutique`
      `kubectl rollout restart deployment/shippingservice -n online-boutique`
      `kubectl rollout restart deployment/cartservice -n online-boutique`
   b) Correctif durable : Mettre en place une automatisation ou une sonde de health-check gRPC post-reboot K3s pour relancer automatiquement les workloads du mesh Ambient.
   c) Prévention : Surveiller les métriques de connectivité ztunnel après chaque maintenance de nœud.

Confiance : haute — confirmée par les codes d'erreur gRPC 14 mesurés, l'état Running des pods et la forte récurrence avec les incidents documentés le même jour sur ce cluster.

---

## 🤖 Diagnostic CheckoutHighLatencyP99 — 2026-07-28 14:16 UTC

| Date | Type | Alerte | Sévérité | SLO |
|---|---|---|---|---|
| 2026-07-28 14:16 UTC | diagnostic | CheckoutHighLatencyP99 | warning | checkout_latency |

**Verdict** : Verdict: Dégradation de la latence P99 du service `checkoutservice` à 4737 ms causée par des délais de traitement internes/amonts combinés aux goulots d'étranglement des dépendances en aval.

Verdict: Dégradation de la latence P99 du service `checkoutservice` à 4737 ms causée par des délais de traitement internes/amonts combinés aux goulots d'étranglement des dépendances en aval.

1. **Cause racine la plus probable** : Le service `checkoutservice` subit une latence P99 élevée (4575–4737 ms, dépassant le seuil de 1000 ms) en raison d'une accumulation de latence dans ses appels synchrones en aval (`cartservice`, `paymentservice`, `shippingservice`, `emailservice`, etc.) ainsi que d'une dégradation de la latence globale propagée depuis le frontend (P99 à 2436 ms). L'analyse des taux d'erreur gRPC ne montre pas de rupture mesh totale (code 14) sur `checkoutservice` lui-même, mais des appels lents et des retries/délais accumulés dans les maillons de la chaîne de commande.
2. **Preuves** :
   - **SLI / Métriques** : PromQL `histogram_quantile(0.99, ...)` indique un P99 de `checkoutservice` à **4737.5 ms** et `frontend` à **2436 ms**.
   - **Codes gRPC / Appels par service** : `sum by (destination_workload, source_workload, grpc_response_status)` confirme que `checkoutservice` appelle normalement `cartservice`, `currencyservice`, `emailservice`, `paymentservice`, `productcatalogservice`, et `shippingservice` avec un statut gRPC `0` (OK), mais que les durées cumulées des requêtes traversant ces dépendances s'allongent fortement. On observe par ailleurs de légères erreurs gRPC `4` (INVALID_ARGUMENT) sur `adservice` (taux ~0.13 req/s) sans impact direct bloquant sur le checkout.
   - **État des pods** : Les pods (ex. `checkoutservice-5fb8d7ddc-tk6sz`, `paymentservice-8dc7c6568-bddxb`, `shippingservice-6474f8cd79-fkg74`, etc.) sont `Running` et `Ready`, mais présentent de multiples redémarrages (ex. 26 redémarrages sur le pod checkout), indiquant une instabilité sous-jacente ou des contraintes de ressources/probes.
3. **Vérification clé** : Les pods de `checkoutservice` et de ses dépendances sont `Running` / `Ready`. Cependant, en raison de la complexité des flux gRPC synchrones en chaîne et d'éventuelles micro-coupures de routage Ambient ou de saturations, la latence s'envole de manière critique tout en restant `Ready` du point de vue de Kubernetes (panne de performance invisible pour un simple check de l'état du pod).
4. **Actions CORRECTIVES recommandées** :
   a) **Mitigation immédiate** : Effectuer un redémarrage progressif (`rollout restart`) des déploiements impliqués dans le parcours de commande pour réinitialiser les connexions du mesh Istio Ambient et purger les files d'attente/états dégradés :
      - `kubectl rollout restart deployment/checkoutservice -n online-boutique`
      - `kubectl rollout restart deployment/paymentservice -n online-boutique`
      - `kubectl rollout restart deployment/shippingservice -n online-boutique`
      - `kubectl rollout restart deployment/cartservice -n online-boutique`
   b) **Correctif durable** : Analyser les limites de ressources (CPU/Memory requests et limits) des pods de `checkoutservice` et surveiller les saturations éventuelles sur `redis-cart` ou les backends de paiement.
   c) **Prévention** : Mettre en place des alertes de saturation amont et affiner les timeouts gRPC entre `checkoutservice` et ses services dépendants pour éviter les effets d'amplification de latence en cascade.

Confiance : moyenne — la latence P99 est directement mesurée et confirmée par Prometheus, mais l'origine exacte de la contention interne nécessite un tracing fin (Tempo) pour départager un problème de CPU/ressource d'un problème de connectivité mesh Ambient.
