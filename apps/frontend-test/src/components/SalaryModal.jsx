import React from 'react';
import { X, DollarSign, Award, Calendar } from 'lucide-react';

export default function SalaryModal({ salaryData, onClose }) {
  if (!salaryData) return null;

  const formattedSalary = salaryData.salary
    ? new Intl.NumberFormat('ko-KR', { style: 'currency', currency: 'KRW' }).format(salaryData.salary)
    : '비공개';

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div className="avatar" style={{ background: 'var(--success-light)', color: 'var(--success)' }}>
              <DollarSign size={20} />
            </div>
            <div>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>{salaryData.name} 직원 급여 정보</h2>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>{salaryData.department} / {salaryData.position}</p>
            </div>
          </div>
          <button className="btn btn-secondary" style={{ padding: '0.4rem', borderRadius: '50%' }} onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        <div style={{ background: 'var(--bg-card)', padding: '1.5rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-color)', marginBottom: '1.5rem' }}>
          <span style={{ fontSize: '0.875rem', color: 'var(--text-muted)' }}>현재 책정 급여 (연봉)</span>
          <div style={{ fontSize: '2rem', fontWeight: 800, color: 'var(--success)', marginTop: '0.25rem' }}>
            {formattedSalary}
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <button className="btn btn-secondary" onClick={onClose}>닫기</button>
        </div>
      </div>
    </div>
  );
}
