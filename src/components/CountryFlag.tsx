import React from 'react';
import { getCountryAccent } from '../shared/countries';

interface CountryFlagProps {
  code: string | null | undefined;
  size?: 'sm' | 'md' | 'lg';
}

export const CountryFlag: React.FC<CountryFlagProps> = ({ code, size = 'md' }) => {
  const upper = (code || '').trim().toUpperCase();
  const dims =
    size === 'lg'
      ? { w: 42, h: 30, font: 13, radius: 6 }
      : size === 'sm'
      ? { w: 22, h: 16, font: 9, radius: 3 }
      : { w: 30, h: 21, font: 11, radius: 4 };

  const svgContent = renderVectorFlag(upper);

  if (svgContent) {
    return (
      <span
        className="country-flag-wrap"
        style={{
          width: dims.w,
          height: dims.h,
          borderRadius: dims.radius,
        }}
        title={upper}
      >
        <svg viewBox="0 0 36 24" width={dims.w} height={dims.h} xmlns="http://www.w3.org/2000/svg">
          {svgContent}
        </svg>
      </span>
    );
  }

  const accent = getCountryAccent(upper);
  return (
    <span
      className="country-code-badge"
      style={{
        width: dims.w,
        height: dims.h,
        fontSize: dims.font,
        borderRadius: dims.radius,
        background: `linear-gradient(135deg, ${accent}, #1E293B)`,
      }}
    >
      {upper && upper !== 'UNKNOWN' ? upper.slice(0, 2) : '?'}
    </span>
  );
};

function renderVectorFlag(code: string): React.ReactNode | null {
  switch (code) {
    case 'US':
      return (
        <>
          <rect width="36" height="24" fill="#B22234" />
          <path
            d="M0,3.4h36 M0,7.2h36 M0,11h36 M0,14.8h36 M0,18.6h36 M0,22.4h36"
            stroke="#FFF"
            strokeWidth="1.9"
          />
          <rect width="15.5" height="13" fill="#3C3B6E" />
          <g fill="#FFF">
            <circle cx="3" cy="2.8" r="0.9" />
            <circle cx="7.7" cy="2.8" r="0.9" />
            <circle cx="12.4" cy="2.8" r="0.9" />
            <circle cx="5.3" cy="5.2" r="0.9" />
            <circle cx="10" cy="5.2" r="0.9" />
            <circle cx="3" cy="7.6" r="0.9" />
            <circle cx="7.7" cy="7.6" r="0.9" />
            <circle cx="12.4" cy="7.6" r="0.9" />
            <circle cx="5.3" cy="10.2" r="0.9" />
            <circle cx="10" cy="10.2" r="0.9" />
          </g>
        </>
      );
    case 'JP':
      return (
        <>
          <rect width="36" height="24" fill="#FFFFFF" />
          <circle cx="18" cy="12" r="6.8" fill="#BC002D" />
        </>
      );
    case 'SG':
      return (
        <>
          <rect width="36" height="12" fill="#EF3340" />
          <rect y="12" width="36" height="12" fill="#FFFFFF" />
          <circle cx="9.2" cy="6" r="4.1" fill="#FFFFFF" />
          <circle cx="10.7" cy="6" r="3.6" fill="#EF3340" />
          <g fill="#FFFFFF">
            <circle cx="11.2" cy="4.2" r="0.65" />
            <circle cx="13.1" cy="5.5" r="0.65" />
            <circle cx="12.4" cy="7.7" r="0.65" />
            <circle cx="10.0" cy="7.7" r="0.65" />
            <circle cx="9.3" cy="5.5" r="0.65" />
          </g>
        </>
      );
    case 'HK':
      return (
        <>
          <rect width="36" height="24" fill="#DE2910" />
          <g fill="#FFFFFF" transform="translate(18,12)">
            <ellipse cx="0" cy="-4.2" rx="1.9" ry="3.6" transform="rotate(0)" />
            <ellipse cx="0" cy="-4.2" rx="1.9" ry="3.6" transform="rotate(72)" />
            <ellipse cx="0" cy="-4.2" rx="1.9" ry="3.6" transform="rotate(144)" />
            <ellipse cx="0" cy="-4.2" rx="1.9" ry="3.6" transform="rotate(216)" />
            <ellipse cx="0" cy="-4.2" rx="1.9" ry="3.6" transform="rotate(288)" />
          </g>
        </>
      );
    case 'TW':
      return (
        <>
          <rect width="36" height="24" fill="#FE0000" />
          <rect width="18" height="12" fill="#000095" />
          <circle cx="9" cy="6" r="3.4" fill="#FFFFFF" />
        </>
      );
    case 'KR':
      return (
        <>
          <rect width="36" height="24" fill="#FFFFFF" />
          <circle cx="18" cy="12" r="5.6" fill="#CD2E3A" />
          <path d="M12.4,12 a5.6,5.6 0 0,0 11.2,0 a2.8,2.8 0 0,0 -5.6,0 a2.8,2.8 0 0,1 -5.6,0Z" fill="#0047A0" />
        </>
      );
    case 'GB':
      return (
        <>
          <rect width="36" height="24" fill="#012169" />
          <path d="M0,0 L36,24 M36,0 L0,24" stroke="#FFF" strokeWidth="4.2" />
          <path d="M0,0 L36,24 M36,0 L0,24" stroke="#C8102E" strokeWidth="2" />
          <path d="M18,0 V24 M0,12 H36" stroke="#FFF" strokeWidth="6.5" />
          <path d="M18,0 V24 M0,12 H36" stroke="#C8102E" strokeWidth="3.8" />
        </>
      );
    case 'DE':
      return (
        <>
          <rect width="36" height="8" fill="#000000" />
          <rect y="8" width="36" height="8" fill="#DD0000" />
          <rect y="16" width="36" height="8" fill="#FFCE00" />
        </>
      );
    case 'NL':
      return (
        <>
          <rect width="36" height="8" fill="#AE1C28" />
          <rect y="8" width="36" height="8" fill="#FFFFFF" />
          <rect y="16" width="36" height="8" fill="#21468B" />
        </>
      );
    case 'FR':
      return (
        <>
          <rect width="12" height="24" fill="#002395" />
          <rect x="12" width="12" height="24" fill="#FFFFFF" />
          <rect x="24" width="12" height="24" fill="#ED2939" />
        </>
      );
    case 'RU':
      return (
        <>
          <rect width="36" height="8" fill="#FFFFFF" />
          <rect y="8" width="36" height="8" fill="#0039A6" />
          <rect y="16" width="36" height="8" fill="#D52B1E" />
        </>
      );
    case 'CA':
      return (
        <>
          <rect width="9" height="24" fill="#FF0000" />
          <rect x="9" width="18" height="24" fill="#FFFFFF" />
          <rect x="27" width="9" height="24" fill="#FF0000" />
          <polygon points="18,5 20,10 23,9.5 21,13.5 22,15.5 18,15 18,19 18,15 14,15.5 15,13.5 13,9.5 16,10" fill="#FF0000" />
        </>
      );
    case 'AU':
      return (
        <>
          <rect width="36" height="24" fill="#00008B" />
          <path d="M0,0 L18,12 M18,0 L0,12" stroke="#FFF" strokeWidth="2.4" />
          <path d="M9,0 V12 M0,6 H18" stroke="#FFF" strokeWidth="3.6" />
          <path d="M9,0 V12 M0,6 H18" stroke="#C8102E" strokeWidth="2" />
          <circle cx="9" cy="18" r="2.2" fill="#FFF" />
          <circle cx="27" cy="6" r="1.3" fill="#FFF" />
          <circle cx="31" cy="11" r="1.3" fill="#FFF" />
          <circle cx="27" cy="18" r="1.5" fill="#FFF" />
          <circle cx="23" cy="12" r="1.3" fill="#FFF" />
        </>
      );
    case 'CN':
      return (
        <>
          <rect width="36" height="24" fill="#EE1C25" />
          <circle cx="7.5" cy="7" r="3" fill="#FFFF00" />
          <g fill="#FFFF00">
            <circle cx="13" cy="3.2" r="1" />
            <circle cx="15.2" cy="5.8" r="1" />
            <circle cx="15" cy="9.2" r="1" />
            <circle cx="12.8" cy="11.6" r="1" />
          </g>
        </>
      );
    case 'VN':
      return (
        <>
          <rect width="36" height="24" fill="#DA251D" />
          <polygon
            points="18,5.5 19.6,10.3 24.6,10.3 20.6,13.3 22.1,18.1 18,15.1 13.9,18.1 15.4,13.3 11.4,10.3 16.4,10.3"
            fill="#FFFF00"
          />
        </>
      );
    case 'TH':
      return (
        <>
          <rect width="36" height="4" fill="#A51931" />
          <rect y="4" width="36" height="4" fill="#F4F5F8" />
          <rect y="8" width="36" height="8" fill="#2D2A4A" />
          <rect y="16" width="36" height="4" fill="#F4F5F8" />
          <rect y="20" width="36" height="4" fill="#A51931" />
        </>
      );
    case 'IN':
      return (
        <>
          <rect width="36" height="8" fill="#FF9933" />
          <rect y="8" width="36" height="8" fill="#FFFFFF" />
          <rect y="16" width="36" height="8" fill="#138808" />
          <circle cx="18" cy="12" r="2.8" fill="none" stroke="#000080" strokeWidth="1.2" />
        </>
      );
    default:
      return null;
  }
}
