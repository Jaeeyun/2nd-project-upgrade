import React from 'react';
import { Building2, User, LogOut, ShieldCheck } from 'lucide-react';

export default function Navbar({ currentUser }) {
  const getRoleClass = (roles = []) => {
    if (roles.includes('admin')) return 'admin';
    if (roles.includes('manager')) return 'manager';
    return 'staff';
  };

  const getRoleText = (roles = []) => {
    if (roles.includes('admin')) return 'Admin';
    if (roles.includes('manager')) return 'HR Manager';
    return 'Staff';
  };

  return (
    <nav className="navbar">
      <div className="navbar-brand">
        <Building2 size={28} style={{ color: '#6366f1' }} />
        <span>HR System (EKS MSA)</span>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        {currentUser && (
          <>
            <div className="user-badge">
              <User size={18} style={{ color: '#94a3b8' }} />
              <span style={{ fontWeight: 600 }}>{currentUser.name}</span>
              <span style={{ color: '#64748b' }}>({currentUser.department})</span>
              <span className={`role-pill ${getRoleClass(currentUser.roles)}`}>
                <ShieldCheck size={12} style={{ display: 'inline', marginRight: '4px' }} />
                {getRoleText(currentUser.roles)}
              </span>
            </div>
            {/* 로그인/세션은 Pomerium이 관리합니다. 아래 링크는 Pomerium 표준 로그아웃 경로 예시이며,
                실제 Pomerium 설정에 맞는 경로로 확인/조정이 필요합니다. */}
            <a className="btn btn-secondary" href="/.pomerium/sign_out">
              <LogOut size={16} /> 로그아웃
            </a>
          </>
        )}
      </div>
    </nav>
  );
}
