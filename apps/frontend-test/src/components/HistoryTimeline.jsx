import React from 'react';
import { X, History, Clock, ArrowRight } from 'lucide-react';

export default function HistoryTimeline({ historyData, employeeName, onClose }) {
  const filteredHistory = historyData.filter(item => item.old_value !== item.new_value);

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '640px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div className="avatar" style={{ background: 'var(--warning-light)', color: 'var(--warning)' }}>
              <History size={20} />
            </div>
            <div>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 700 }}>{employeeName ? `${employeeName} 인사 변경 이력` : '부서 인사 변경 이력'}</h2>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>총 {filteredHistory.length}건의 감사 로그 기록</p>
            </div>
          </div>
          <button className="btn btn-secondary" style={{ padding: '0.4rem', borderRadius: '50%' }} onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        <div style={{ maxHeight: '400px', overflowY: 'auto', paddingRight: '0.5rem' }}>
          {filteredHistory.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
              변경 이력 기록이 없습니다.
            </div>
          ) : (
            filteredHistory.map((item, idx) => (
              <div
                key={idx}
                style={{
                  padding: '1rem',
                  marginBottom: '0.75rem',
                  border: '1px solid var(--border-color)',
                  borderRadius: 'var(--radius-md)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.5rem'
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.8rem', color: 'var(--text-dim)' }}>
                  <span style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                    <Clock size={12} /> {new Date(item.changed_at || Date.now()).toLocaleString('ko-KR')}
                  </span>
                  <span className="role-pill staff">{item.changed_by || 'HR Admin'}</span>
                </div>

                <div style={{ fontSize: '0.95rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span>{item.change_type === 'POSITION' ? '직급 변경' : '급여 변경'}</span>
                  <ArrowRight size={14} style={{ color: 'var(--primary)' }} />
                  <span style={{ color: 'var(--success)' }}>
                    {item.old_value} ➔ {item.new_value}
                  </span>
                </div>

                {item.reason && (
                  <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>
                    사유: "{item.reason}"
                  </div>
                )}
              </div>
            ))
          )}
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '1.5rem' }}>
          <button className="btn btn-secondary" onClick={onClose}>닫기</button>
        </div>
      </div>
    </div>
  );
}
