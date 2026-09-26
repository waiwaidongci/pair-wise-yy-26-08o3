import os, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from database import DomainError, VulnerabilityDB

class VulnerabilityFlowTest(unittest.TestCase):
    def setUp(self):
        fd,self.path=tempfile.mkstemp(suffix=".db"); os.close(fd); self.db=VulnerabilityDB(self.path)
        self.reporter=self.db.add_user("报告人","reporter","研究所"); self.coord=self.db.add_user("协调员","coordinator","响应中心"); self.maint=self.db.add_user("维护者","maintainer","项目组"); self.outsider=self.db.add_user("旁观者","reporter","外部")
        self.product=self.db.add_product("网关","项目组")
        self.report=self.db.create_report("鉴权绕过",self.product,self.reporter,"特制请求可绕过鉴权","2026-10-30",["3.2.0"])
    def tearDown(self): self.db.close(); os.unlink(self.path)
    def _advance_to_resolved(self):
        self.db.add_member(self.report,self.maint,"maintainer",self.coord)
        self.db.set_status(self.report,"triaged",self.coord)
        self.db.set_status(self.report,"fixing",self.coord)
        self.db.set_fix_plan(self.report,self.maint,"增加鉴权前置校验", "2026-10-20")
        self.db.set_status(self.report,"resolved",self.coord)
        self.db.create_advisory_draft(self.report,"受影响版本 3.2.0。请升级到 3.2.1。",self.coord)
    def test_full_disclosure_flow_and_early_publish_rejected(self):
        self._advance_to_resolved()
        with self.assertRaisesRegex(DomainError,"提前披露"):
            self.db.publish_report(self.report,self.coord,"2026-10-01")
        self.db.publish_report(self.report,self.coord,"2026-10-30")
        advisory=self.db.get_advisory(self.report,self.outsider)
        self.assertEqual("published",advisory["status"])
        self.assertTrue(self.db.notifications_for(self.maint))
    def test_denies_outsider_and_duplicate_report(self):
        with self.assertRaisesRegex(DomainError,"无权"):
            self.db.get_report_for_user(self.report,self.outsider)
        with self.assertRaisesRegex(DomainError,"重复"):
            self.db.create_report("重复问题",self.product,self.reporter,"相同版本的另一份报告","2026-11-01",["3.2.0"])
        self.db.add_member(self.report,self.maint,"maintainer",self.coord)
        self.db.add_evidence(self.report,"协调材料","secret","coordinator",self.coord)
        visible=self.db.get_report_for_user(self.report,self.maint)
        self.assertEqual([],visible["evidence"])
    def _setup_evidence_and_member(self):
        self.db.add_member(self.report,self.maint,"maintainer",self.coord)
        return self.db.add_evidence(self.report,"复现脚本","payload","private",self.reporter)
    def test_grant_revoke_and_regrant_flow(self):
        ev=self._setup_evidence_and_member()
        other=self.db.add_user("另一维护者","maintainer","项目组"); self.db.add_member(self.report,other,"maintainer",self.coord)
        self.assertEqual([],self.db.get_report_for_user(self.report,self.maint)["evidence"])
        with self.assertRaisesRegex(DomainError,"协调员"):
            self.db.grant_evidence_access(self.report,ev,self.maint,"2026-10-01",self.maint)
        with self.assertRaisesRegex(DomainError,"维护者成员"):
            self.db.grant_evidence_access(self.report,ev,self.outsider,"2026-10-01",self.coord)
        with self.assertRaisesRegex(DomainError,"不能早于今天"):
            self.db.grant_evidence_access(self.report,ev,self.maint,"2020-01-01",self.coord)
        self.db.grant_evidence_access(self.report,ev,self.maint,"2026-10-01",self.coord)
        view=self.db.get_report_for_user(self.report,self.maint)
        self.assertEqual([ev],[e["id"] for e in view["evidence"]])
        self.assertEqual(1,len(view["grants_active"]))
        self.assertEqual([],self.db.get_report_for_user(self.report,other)["evidence"])
        self.assertEqual([],self.db.get_report_for_user(self.report,other)["grants_active"])
        self.db.grant_evidence_access(self.report,ev,self.maint,"2026-10-20",self.coord)
        view=self.db.get_report_for_user(self.report,self.coord)
        self.assertEqual(1,len(view["grants_active"]))
        self.assertEqual("2026-10-20",view["grants_active"][0]["expires_at"])
        self.assertEqual(["granted","regranted"],[e["action"] for e in view["grants_active"][0]["events"]])
        self.assertEqual("2026-10-01",view["grants_active"][0]["events"][1]["old_expires_at"])
        self.db.revoke_evidence_grant(self.report,ev,self.maint,self.coord)
        view=self.db.get_report_for_user(self.report,self.maint)
        self.assertEqual([],view["evidence"])
        self.assertEqual([],view["grants_active"])
        self.assertEqual("revoked",view["grants_expired"][0]["effective_status"])
        self.assertTrue(any(n["kind"]=="grant_revoked" for n in self.db.notifications_for(self.maint)))
        self.db.grant_evidence_access(self.report,ev,self.maint,"2026-10-25",self.coord)
        self.assertEqual([ev],[e["id"] for e in self.db.get_report_for_user(self.report,self.maint)["evidence"]])
    def test_expired_grant_hides_evidence_until_regranted(self):
        ev=self._setup_evidence_and_member()
        self.db.grant_evidence_access(self.report,ev,self.maint,"2026-10-01",self.coord)
        self.db.conn.execute("UPDATE evidence_grants SET expires_at='2020-01-01'"); self.db.conn.commit()
        view=self.db.get_report_for_user(self.report,self.maint)
        self.assertEqual([],view["evidence"])
        self.assertEqual([],view["grants_active"])
        self.assertEqual("expired",view["grants_expired"][0]["effective_status"])
        self.db.grant_evidence_access(self.report,ev,self.maint,"2026-11-01",self.coord)
        view=self.db.get_report_for_user(self.report,self.maint)
        self.assertEqual([ev],[e["id"] for e in view["evidence"]])
        self.assertEqual("2026-11-01",view["grants_active"][0]["expires_at"])
    def test_publish_closes_all_active_grants(self):
        ev=self._setup_evidence_and_member()
        self.db.grant_evidence_access(self.report,ev,self.maint,"2026-10-25",self.coord)
        self._advance_to_resolved()
        self.db.publish_report(self.report,self.coord,"2026-10-30")
        view=self.db.get_report_for_user(self.report,self.maint)
        self.assertEqual([],view["evidence"])
        self.assertEqual([],view["grants_active"])
        self.assertEqual("closed",view["grants_expired"][0]["effective_status"])
        self.assertEqual("auto_closed",view["grants_expired"][0]["events"][-1]["action"])
        self.assertTrue(any(n["kind"]=="grant_closed" for n in self.db.notifications_for(self.maint)))
        with self.assertRaisesRegex(DomainError,"已公开"):
            self.db.grant_evidence_access(self.report,ev,self.maint,"2026-11-01",self.coord)

if __name__=="__main__": unittest.main()
