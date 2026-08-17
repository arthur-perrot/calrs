-- Per-event-type toggle for the reminder email sent to the HOST.
--
-- Defaults to enabled (1) to preserve existing behavior. Hosts whose own
-- calendar already alerts them before the meeting can disable this to avoid a
-- duplicate notification. The guest reminder is unaffected.
ALTER TABLE event_types ADD COLUMN host_reminder_enabled INTEGER NOT NULL DEFAULT 1;
