import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import EmployeeCard from './components/EmployeeCard';
import SalaryModal from './components/SalaryModal';
import HREditModal from './components/HREditModal';
import HistoryTimeline from './components/HistoryTimeline';
import { Search, RefreshCw, ShieldCheck, UserCheck, UserPlus, X } from 'lucide-react';

const isHRDomain = window.location.hostname.includes('hr.');
const apiBase = isHRDomain ? '/api/hr' : '/api/employee';

export default function App() {
  const [currentUser, setCurrentUser] = useState(null);
  const [employees, setEmployees] = useState([]);
  const [loading, setLoading] = useState(true);
  const [authError, setAuthError] = useState('');
  const [searchQuery, setSearchQuery] = useState('');

  const [salaryModalData, setSalaryModalData] = useState(null);
  const [editEmployeeData, setEditEmployeeData] = useState(null);
  const [historyModalData, setHistoryModalData] = useState(null);
  const [historyTargetName, setHistoryTargetName] = useState('');

  // New Employee Modal State
  const [showAddModal, setShowAddModal] = useState(false);
  const [newEmp, setNewEmp] = useState({
    name: '', department: '개발팀', position: '사원', salary: 45000000, email: '', is_hr: false,
  });

  useEffect(() => {
    load();
  }, []);

  // 로그인한 사람이 누구인지는 백엔드가 Pomerium 헤더 + DB로 결정한다.
  // 프론트는 그 결과(/me)를 그대로 그려줄 뿐, 도메인 이름으로 권한을 추측하지 않는다.
  const load = async () => {
    setLoading(true);
    setAuthError('');
    try {
      const meRes = await fetch(`${apiBase}/me`);
      if (!meRes.ok) {
        const body = await meRes.json().catch(() => ({}));
        setAuthError(body.detail || `인증에 실패했습니다 (HTTP ${meRes.status})`);
        setCurrentUser(null);
        return;
      }
      const me = await meRes.json();
      const user = {
        name: me.name,
        department: me.department,
        roles: isHRDomain ? ['admin', 'manager'] : ['staff'],
      };
      setCurrentUser(user);

      if (isHRDomain) {
        await fetchEmployees();
      } else {
        // 직원 셀프서비스: 본인 정보만 카드 1개로 표시
        setEmployees([me]);
      }
    } catch (err) {
      console.error('Fetch error:', err);
      setAuthError('서버에 연결할 수 없습니다.');
    } finally {
      setLoading(false);
    }
  };

  const fetchEmployees = async () => {
    try {
      const res = await fetch(`${apiBase}/employees`);
      if (res.ok) {
        setEmployees(await res.json());
      }
    } catch (err) {
      console.error('Fetch error:', err);
    }
  };

  const handleCreateEmployee = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch('/api/hr/employees', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newEmp),
      });
      if (res.ok) {
        await fetchEmployees();
        setShowAddModal(false);
        setNewEmp({ name: '', department: '개발팀', position: '사원', salary: 45000000, email: '', is_hr: false });
      } else {
        const body = await res.json().catch(() => ({}));
        alert(body.detail || '등록에 실패했습니다.');
      }
    } catch (err) {
      console.error('Create error:', err);
    }
  };

  const handleViewSalary = async (empId) => {
    try {
      const url = isHRDomain ? `${apiBase}/employees/${empId}/salary` : `${apiBase}/me`;
      const res = await fetch(url);
      if (res.ok) {
        setSalaryModalData(await res.json());
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleViewHistory = async (empId) => {
    const target = employees.find((e) => e.id === empId);
    setHistoryTargetName(target ? target.name : '');
    try {
      const url = isHRDomain ? `${apiBase}/employees/${empId}/history` : `${apiBase}/me/history`;
      const res = await fetch(url);
      if (res.ok) {
        setHistoryModalData(await res.json());
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleHREditSave = async ({ employeeId, position, salary, reason }) => {
    try {
      await fetch(`/api/hr/employees/${employeeId}/position`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ new_position: position, reason }),
      });
      await fetch(`/api/hr/employees/${employeeId}/salary`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ new_salary: Number(salary), reason }),
      });
      await fetchEmployees();
    } catch (err) {
      console.error(err);
    }
    setEditEmployeeData(null);
  };

  const filteredEmployees = employees.filter(
    (e) => e.name.includes(searchQuery) || e.position.includes(searchQuery)
  );

  const isHRManager = isHRDomain;

  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: '4rem', color: 'var(--text-muted)' }}>
        불러오는 중...
      </div>
    );
  }

  if (authError) {
    return (
      <div style={{ maxWidth: '480px', margin: '4rem auto', padding: '2rem', textAlign: 'center' }}>
        <h2 style={{ marginBottom: '0.75rem' }}>접근할 수 없습니다</h2>
        <p style={{ color: 'var(--text-muted)' }}>{authError}</p>
      </div>
    );
  }

  return (
    <div>
      <Navbar currentUser={currentUser} />

      <main className="container">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: '2rem', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <h1 style={{ fontSize: '1.8rem', fontWeight: 800, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              {isHRDomain ? <ShieldCheck size={28} style={{ color: 'var(--primary)' }} /> : <UserCheck size={28} style={{ color: 'var(--success)' }} />}
              {isHRDomain ? '전사 HR 인사관리 포털 (RDS DB 실시간 쿼리)' : '마이 페이지 (RDS DB 본인 정보)'}
            </h1>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', marginTop: '0.25rem' }}>
              {isHRDomain ? '🛡️ 인사팀 관리자 모드: AWS RDS PostgreSQL 실시간 신규 등록, 수정 및 이력 저장 (인사팀 소속은 관리 대상에서 제외)' : '👤 직원 개인 모드: AWS RDS PostgreSQL 실시간 DB 본인 정보 전용 조회'}
            </p>
          </div>

          {isHRDomain && (
            <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
              <button className="btn btn-primary" onClick={() => setShowAddModal(true)}>
                <UserPlus size={16} /> 신규 직원 등록
              </button>
              <div className="form-group" style={{ marginBottom: 0, minWidth: '220px' }}>
                <div style={{ position: 'relative' }}>
                  <Search size={16} style={{ position: 'absolute', left: '1rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-dim)' }} />
                  <input
                    type="text"
                    className="form-input"
                    style={{ paddingLeft: '2.5rem' }}
                    placeholder="이름 또는 직급 검색..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                  />
                </div>
              </div>
              <button className="btn btn-secondary" onClick={fetchEmployees}>
                <RefreshCw size={16} /> 새로고침
              </button>
            </div>
          )}
        </div>

        <div className="grid-employees">
          {filteredEmployees.map((emp) => (
            <EmployeeCard
              key={emp.id}
              employee={emp}
              isHRManager={isHRManager}
              onViewSalary={handleViewSalary}
              onViewHistory={handleViewHistory}
              onEdit={(e) => setEditEmployeeData(e)}
            />
          ))}
        </div>
      </main>

      {/* Add Employee Modal */}
      {showAddModal && (
        <div className="modal-overlay">
          <div className="modal-content" style={{ maxWidth: '500px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>➕ 신규 입사자 등록 (RDS DB 저장)</h2>
              <button className="btn btn-secondary" style={{ padding: '0.4rem' }} onClick={() => setShowAddModal(false)}>
                <X size={18} />
              </button>
            </div>
            <form onSubmit={handleCreateEmployee}>
              <div className="form-group">
                <label className="form-label">성명</label>
                <input type="text" className="form-input" required value={newEmp.name} onChange={(e) => setNewEmp({ ...newEmp, name: e.target.value })} placeholder="예: 강감찬" />
              </div>
              <div className="form-group">
                <label className="form-label">부서</label>
                <select className="form-input" value={newEmp.department} onChange={(e) => setNewEmp({ ...newEmp, department: e.target.value })}>
                  <option value="개발팀">개발팀</option>
                  <option value="인사팀">인사팀</option>
                  <option value="영업팀">영업팀</option>
                  <option value="기획팀">기획팀</option>
                </select>
              </div>
              <div className="form-group">
                <label className="form-label">직급</label>
                <input type="text" className="form-input" required value={newEmp.position} onChange={(e) => setNewEmp({ ...newEmp, position: e.target.value })} placeholder="예: 선임 연구원" />
              </div>
              <div className="form-group">
                <label className="form-label">연봉 (원)</label>
                <input type="number" className="form-input" required value={newEmp.salary} onChange={(e) => setNewEmp({ ...newEmp, salary: Number(e.target.value) })} />
              </div>
              <div className="form-group">
                <label className="form-label">이메일</label>
                <input type="email" className="form-input" required value={newEmp.email} onChange={(e) => setNewEmp({ ...newEmp, email: e.target.value })} placeholder="gamchan.kang@company.com" />
              </div>
              <div className="form-group" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <input
                  type="checkbox"
                  id="is_hr"
                  checked={newEmp.is_hr}
                  onChange={(e) => setNewEmp({ ...newEmp, is_hr: e.target.checked })}
                />
                <label htmlFor="is_hr" className="form-label" style={{ marginBottom: 0 }}>
                  인사팀 소속 (체크 시 이 직원 목록/수정 화면에서 제외됩니다)
                </label>
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '1.5rem' }}>
                <button type="button" className="btn btn-secondary" onClick={() => setShowAddModal(false)}>취소</button>
                <button type="submit" className="btn btn-primary">RDS DB에 등록 저장</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {salaryModalData && (
        <SalaryModal salaryData={salaryModalData} onClose={() => setSalaryModalData(null)} />
      )}

      {editEmployeeData && (
        <HREditModal
          employee={editEmployeeData}
          onSave={handleHREditSave}
          onClose={() => setEditEmployeeData(null)}
        />
      )}

      {historyModalData && (
        <HistoryTimeline
          historyData={historyModalData}
          employeeName={historyTargetName}
          onClose={() => setHistoryModalData(null)}
        />
      )}
    </div>
  );
}
