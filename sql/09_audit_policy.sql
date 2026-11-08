-- ============================================================
-- 09 Database level auditing (Lab 14), run as SYSTEM
-- Oracle 21c uses UNIFIED AUDITING: create a policy, then enable it.
-- Records appear in UNIFIED_AUDIT_TRAIL.
-- ============================================================

CREATE AUDIT POLICY tv_evidence_policy
  ACTIONS DELETE ON tv_khi.log_event,
          UPDATE ON tv_khi.log_event,
          DELETE ON tv_lhr.log_event,
          UPDATE ON tv_lhr.log_event,
          DELETE ON tv_isb.log_event,
          UPDATE ON tv_isb.log_event,
          DELETE ON tv_central.incidents,
          DELETE ON tv_central.blocklist,
          UPDATE ON tv_central.detection_rule;

AUDIT POLICY tv_evidence_policy;

-- Classic syntax from the lab manual, for reference only.
-- Oracle 23ai and newer accept only unified auditing, so these lines are commented out:
--   AUDIT DELETE ON tv_khi.log_event BY ACCESS;

PROMPT Audit policy tv_evidence_policy enabled.
