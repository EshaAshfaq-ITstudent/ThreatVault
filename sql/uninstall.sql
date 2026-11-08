-- Removes everything ThreatVault created. Run as SYSTEM.
SET VERIFY OFF
@@config.sql
BEGIN
  EXECUTE IMMEDIATE 'NOAUDIT POLICY tv_evidence_policy';
EXCEPTION WHEN OTHERS THEN NULL;
END;
/
BEGIN
  EXECUTE IMMEDIATE 'DROP AUDIT POLICY tv_evidence_policy';
EXCEPTION WHEN OTHERS THEN NULL;
END;
/
BEGIN
  FOR u IN (SELECT username FROM dba_users
            WHERE username IN ('TV_CENTRAL','TV_KHI','TV_LHR','TV_ISB')) LOOP
    EXECUTE IMMEDIATE 'DROP USER ' || u.username || ' CASCADE';
  END LOOP;
END;
/
DROP DIRECTORY tv_dir;
PROMPT ThreatVault removed.
