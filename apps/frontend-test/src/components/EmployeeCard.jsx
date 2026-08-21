import React from 'react';
import { DollarSign, History, Edit3, Briefcase, Mail } from 'lucide-react';

export default function EmployeeCard({ employee, isHRManager, onViewSalary, onViewHistory, onEdit }) {
  return (
    <div className="employee-card">
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
          <div className="avatar">
            {employee.name ? employee.name[0] : 'E'}
          </div>
          <div>
            <h3 style={{ fontSize: '1.1rem', fontWeight: 700 }}>{employee.name}</h3>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>{employee.position}</p>
          </div>
        </div>
        <span className="role-pill staff">{employee.department}</span>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginBottom: '1.25rem', fontSize: '0.875rem', color: 'var(--text-muted)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Mail size={14} /> <span>{employee.email}</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Briefcase size={14} /> <span>{employee.position}</span>
        </div>
      </div>

      <div style={{ display: 'flex', gap: '0.5rem', borderTop: '1px solid var(--border-color)', paddingTop: '1rem' }}>
        <button className="btn btn-secondary" style={{ flex: 1, padding: '0.4rem 0.6rem', fontSize: '0.8rem' }} onClick={() => onViewSalary(employee.id)}>
          <DollarSign size={14} /> 급여
        </button>
        {isHRManager && (
          <button className="btn btn-primary" style={{ padding: '0.4rem 0.6rem', fontSize: '0.8rem' }} onClick={() => onEdit(employee)}>
            <Edit3 size={14} /> 수정
          </button>
        )}
      </div>
    </div>
  );
}
