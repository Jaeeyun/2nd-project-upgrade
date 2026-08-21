import React, { useState } from 'react';
import { X, Save, Edit3 } from 'lucide-react';

export default function HREditModal({ employee, onSave, onClose }) {
  const [position, setPosition] = useState(employee.position || '');
  const [salary, setSalary] = useState(employee.salary || 0);
  const [reason, setReason] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    await onSave({ employeeId: employee.id, position, salary, reason });
    setLoading(false);
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div className="avatar" style={{ background: 'var(--primary-light)', color: 'var(--primary)' }}>
              <Edit3 size={20} />
            </div>
            <div>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>{employee.name} 인사정보 수정 (HR)</h2>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>{employee.department}</p>
            </div>
          </div>
          <button className="btn btn-secondary" style={{ padding: '0.4rem', borderRadius: '50%' }} onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">직급 (Position)</label>
            <input
              type="text"
              className="form-input"
              value={position}
              onChange={(e) => setPosition(e.target.value)}
              required
            />
          </div>

          <div className="form-group">
            <label className="form-label">급여 (원)</label>
            <input
              type="number"
              className="form-input"
              value={salary}
              onChange={(e) => setSalary(Number(e.target.value))}
              required
            />
          </div>

          <div className="form-group">
            <label className="form-label">변경 사유 (Reason for Audit Log)</label>
            <input
              type="text"
              className="form-input"
              placeholder="예: 2026년 정기 인상 및 정기 승진"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              required
            />
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '1.5rem' }}>
            <button type="button" className="btn btn-secondary" onClick={onClose}>취소</button>
            <button type="submit" className="btn btn-primary" disabled={loading}>
              <Save size={16} /> {loading ? '저장 중...' : '변경사항 저장'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
