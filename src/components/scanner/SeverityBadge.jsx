import React from 'react';
import { getBusinessRisk } from '../../lib/utils/translations';

const SeverityBadge = ({ severity }) => {
  const risk = getBusinessRisk(severity);
  
  return (
    <span className={risk.badge}>{risk.label}</span>
  );
};

export default SeverityBadge;
