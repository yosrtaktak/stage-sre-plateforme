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

CREATE TABLE IF NOT EXISTS incidents (
  id           BIGSERIAL PRIMARY KEY,
  fingerprint  TEXT UNIQUE,          -- fingerprint Alertmanager : la clé neutre
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

-- L'utilisateur applicatif `incident` (créé au premier boot) possède tout.
ALTER TABLE incidents       OWNER TO incident;
ALTER TABLE incident_events OWNER TO incident;
ALTER VIEW  incident_metrics OWNER TO incident;
