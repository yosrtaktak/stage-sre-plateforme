-- =============================================================================
--  Schéma incident_db — NOTRE vérité d'incident, indépendante de l'outil
--  d'astreinte (point 4 de la checklist anti lock-in). Idempotent : rejouable.
--  Application (en tant que superuser local du pod, ownership remis à
--  l'utilisateur `incident`) :
--    kubectl -n monitoring exec -i deploy/incident-postgres -- \
--      psql -U postgres -d incident_db < manifests/incident-tool/schema-incident-db.sql
--  AUCUN credential dans ce fichier (repo public) — les rôles applicatifs
--  (grafana_ro...) se créent par commande séparée avec mot de passe en Secret.
-- =============================================================================

-- 06/08/2026 : fingerprint N'EST PLUS UNIQUE — une alerte récurrente crée un
-- NOUVEL épisode après chaque clôture (sinon plus aucun incident enregistré
-- après le premier). Migration d'une base existante :
--   ALTER TABLE incidents DROP CONSTRAINT IF EXISTS incidents_fingerprint_key;
--   CREATE INDEX IF NOT EXISTS incidents_fingerprint ON incidents(fingerprint);
CREATE TABLE IF NOT EXISTS incidents (
  id           BIGSERIAL PRIMARY KEY,
  fingerprint  TEXT,                 -- fingerprint Alertmanager : la clé neutre
  external_id  TEXT,                 -- id chez l'outil d'astreinte (informatif)
  alertname    TEXT NOT NULL,
  service      TEXT,                 -- label service/slo si présent
  severity     TEXT,
  status       TEXT NOT NULL DEFAULT 'open',   -- open | acked | closed
  opened_at    TIMESTAMPTZ NOT NULL,
  acked_at     TIMESTAMPTZ,          -- premier ack -> MTTA par construction
  closed_at    TIMESTAMPTZ,          -- résolution -> MTTR par construction
  summary      TEXT
);

CREATE TABLE IF NOT EXISTS incident_events (
  id           BIGSERIAL PRIMARY KEY,
  incident_id  BIGINT REFERENCES incidents(id) ON DELETE CASCADE,
  at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  actor        TEXT NOT NULL,        -- 'alertmanager' | 'agent-sre' | nom humain
  action       TEXT NOT NULL,        -- created|acknowledged|closed|diagnosed|pr_opened|note
  detail       TEXT                  -- texte libre + URL de preuve éventuelle
);

CREATE INDEX IF NOT EXISTS incident_events_incident ON incident_events(incident_id, at);
CREATE INDEX IF NOT EXISTS incidents_opened ON incidents(opened_at);
CREATE INDEX IF NOT EXISTS incidents_fingerprint ON incidents(fingerprint);

-- Vue MTTA/MTTR par service et sévérité — la source du dashboard Grafana.
-- Par service et sévérité, JAMAIS par personne (choix assumé de la synthèse).
CREATE OR REPLACE VIEW incident_metrics AS
SELECT
  coalesce(service, 'inconnu')                                   AS service,
  coalesce(severity, 'inconnu')                                  AS severity,
  count(*)                                                       AS incidents,
  round(avg(EXTRACT(EPOCH FROM (acked_at  - opened_at)))::numeric, 0) AS mtta_s,
  round(avg(EXTRACT(EPOCH FROM (closed_at - opened_at)))::numeric, 0) AS mttr_s,
  count(*) FILTER (WHERE acked_at IS NULL AND status = 'open')   AS sans_ack
FROM incidents
GROUP BY 1, 2;

-- 10/08/2026 : la vue all-time ci-dessus devient illisible dès qu'un incident
-- traîne (un ack au debrief 3 jours après l'ouverture => MTTA « 1.64 days »
-- qui écrase la moyenne). La vue fenêtrée est celle que le dashboard affiche ;
-- l'all-time reste disponible pour l'historique long.
CREATE OR REPLACE VIEW incident_metrics_7j AS
SELECT
  coalesce(service, 'inconnu')                                   AS service,
  coalesce(severity, 'inconnu')                                  AS severity,
  count(*)                                                       AS incidents,
  round(avg(EXTRACT(EPOCH FROM (acked_at  - opened_at)))::numeric, 0) AS mtta_s,
  round(avg(EXTRACT(EPOCH FROM (closed_at - opened_at)))::numeric, 0) AS mttr_s,
  count(*) FILTER (WHERE acked_at IS NULL AND status = 'open')   AS sans_ack
FROM incidents
WHERE opened_at > now() - interval '7 days'
GROUP BY 1, 2;

-- L'utilisateur applicatif `incident` (créé au premier boot) possède tout.
ALTER TABLE incidents       OWNER TO incident;
ALTER TABLE incident_events OWNER TO incident;
ALTER VIEW  incident_metrics OWNER TO incident;
ALTER VIEW  incident_metrics_7j OWNER TO incident;

