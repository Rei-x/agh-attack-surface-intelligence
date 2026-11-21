import { useId } from 'react';
import { cn } from '@/lib/utils';

/**
 * Dzięcioł brand art, drawn from the cover illustration (same coordinates, cropped by
 * viewBox). Colours: ink #141716, off-white #e9e5dc, woodpecker red #e8392f.
 * Animations live in index.css (wp-* classes) and stop under prefers-reduced-motion.
 */
export const WOODPECKER_RED = '#e8392f';

/** Head paths shared by the mark, the loader and the full bird. */
function Head({ beak = 'long' }: { beak?: 'long' | 'short' }) {
  const tip = beak === 'long' ? 1262 : 1232;
  return (
    <>
      <circle cx="1112" cy="430" r="62" className="wp-head" />
      <path d="M1090 432 C1104 410 1150 410 1166 432 C1150 452 1108 456 1090 432 Z" fill="#e9e5dc" />
      <path d="M1084 456 C1110 468 1146 464 1170 452 L1172 464 C1146 478 1108 480 1080 470 Z" fill="#0d0f0e" />
      <path d="M1060 412 C1056 372 1084 352 1118 360 C1100 372 1090 392 1092 418 Z" fill={WOODPECKER_RED} />
      <path d="M1066 384 L1046 372 L1066 400 Z" fill={WOODPECKER_RED} />
      <circle cx="1134" cy="414" r="9" fill="#e9e5dc" />
      <circle cx="1136" cy="414" r="5" fill="#050605" />
      <circle cx="1138" cy="412" r="1.6" fill="#fff" />
      <path d={`M1166 410 L${tip} 434 L${tip - 22} 438 L1166 446 Z`} fill="#c9c3b6" />
      <path d={`M1166 428 L${tip} 434 L1166 446 Z`} fill="#8f8a80" />
    </>
  );
}

/** Brand mark: woodpecker head with the red crest. Sized by height (className h-*). */
export function WoodpeckerMark({ className, title = 'Dzięcioł' }: { className?: string; title?: string }) {
  return (
    <svg
      viewBox="1040 346 196 150"
      role="img"
      aria-label={title}
      className={cn('h-6 w-auto shrink-0 overflow-visible', className)}
    >
      <Head beak="short" />
    </svg>
  );
}

/**
 * Pecking loader: the head knocks twice on a strip of bark, red ripple on impact
 * ("stuk stuk"). Decorative; pair it with text for screen readers.
 */
export function PeckSpinner({ className }: { className?: string }) {
  return (
    <svg
      viewBox="1040 346 236 150"
      aria-hidden
      // "wp-size-auto" (no CSS) opts out of the buttons' [&_svg:not([class*='size-'])]:size-*
      // rule, which would squash the bird into a square.
      className={cn('wp-anim wp-size-auto h-4 w-auto shrink-0 overflow-visible', className)}
    >
      <rect x="1240" y="352" width="36" height="140" className="wp-bark" />
      <circle cx="1240" cy="434" r="16" className="wp-ring" />
      <circle cx="1240" cy="434" r="16" className="wp-ring wp-ring-2" />
      <g className="wp-jab">
        <Head beak="short" />
      </g>
    </svg>
  );
}

/** Loading state: pecking bird + label, centred like <Empty/>. */
export function PeckLoader({ label = 'Ładowanie…', className }: { label?: string; className?: string }) {
  return (
    <div
      role="status"
      className={cn(
        'flex flex-col items-center justify-center gap-2.5 py-10 text-center text-xs text-muted-foreground',
        className
      )}
    >
      <PeckSpinner className="h-6" />
      <span>{label}</span>
    </div>
  );
}

/**
 * Cover scene for the login page: the whole bird on a trunk, pecking, with red ripples
 * around the hole. viewBox crops the 1600x1200 cover to the bird + a slice of trunk.
 */
export function WoodpeckerScene({ className }: { className?: string }) {
  const uid = useId().replace(/:/g, '');
  const trunk = `wp-trunk-${uid}`;
  const glow = `wp-glow-${uid}`;
  const wing = `wp-wing-${uid}`;
  return (
    <svg viewBox="940 300 520 800" aria-hidden className={cn('wp-anim block h-full w-auto', className)}>
      <defs>
        <linearGradient id={trunk} x1="0" x2="1">
          <stop offset="0" stopColor="#171b19" />
          <stop offset=".5" stopColor="#1f2421" />
          <stop offset="1" stopColor="#121514" />
        </linearGradient>
        <radialGradient
          id={glow}
          cx="0"
          cy="0"
          r="1"
          gradientUnits="userSpaceOnUse"
          gradientTransform="translate(1300 560) scale(460)"
        >
          <stop offset="0" stopColor={WOODPECKER_RED} stopOpacity=".22" />
          <stop offset="1" stopColor={WOODPECKER_RED} stopOpacity="0" />
        </radialGradient>
        <clipPath id={wing}>
          <path d="M1046 470 C1010 505 1000 600 1024 676 L1078 656 C1068 594 1072 530 1084 486 Z" />
        </clipPath>
      </defs>

      <circle cx="1300" cy="560" r="460" fill={`url(#${glow})`} />
      <rect x="1300" y="-10" width="320" height="1220" fill={`url(#${trunk})`} />
      <rect x="1300" y="-10" width="3" height="1220" fill="#2c322f" />
      <ellipse cx="1306" cy="560" rx="9" ry="14" fill="#050605" />
      <circle className="wp-scene-ring" cx="1302" cy="560" r="40" />
      <circle className="wp-scene-ring wp-r2" cx="1302" cy="560" r="40" />
      <circle className="wp-scene-ring wp-r3" cx="1302" cy="560" r="40" />

      <g className="wp-scene-peck">
        <g transform="translate(38 126)">
          <path d="M1060 690 L1150 900 L1118 904 L1030 712 Z" fill="#141716" />
          <path d="M1084 700 L1166 880 L1150 900 L1068 708 Z" fill="#202523" />
          <path
            d="M1066 420 C990 446 962 560 980 650 C994 716 1052 738 1094 700 C1140 656 1146 536 1124 456 Z"
            fill="#141716"
          />
          <path d="M1112 470 C1140 540 1138 640 1100 696 C1124 640 1126 548 1104 476 Z" fill="#e9e5dc" />
          <path d="M1030 452 C1050 470 1066 500 1070 540 C1050 520 1036 492 1030 452 Z" fill="#e9e5dc" />
          <path d="M1046 470 C1010 505 1000 600 1024 676 L1078 656 C1068 594 1072 530 1084 486 Z" fill="#0d0f0e" />
          <g clipPath={`url(#${wing})`} fill="#e9e5dc">
            <rect x="990" y="540" width="120" height="9" transform="rotate(-14 1050 544)" />
            <rect x="990" y="574" width="120" height="9" transform="rotate(-14 1050 578)" />
            <rect x="990" y="608" width="120" height="9" transform="rotate(-14 1050 612)" />
            <rect x="990" y="642" width="120" height="9" transform="rotate(-14 1050 646)" />
          </g>
          <path d="M1074 690 C1096 690 1116 708 1112 730 C1092 734 1070 718 1074 690 Z" fill={WOODPECKER_RED} />
          <g stroke="#3b403d" strokeWidth="7" strokeLinecap="round" fill="none">
            <path d="M1110 610 L1150 600 L1170 590" />
            <path d="M1150 600 L1172 612" />
            <path d="M1104 650 L1146 646 L1168 636" />
          </g>
          <g className="wp-scene-head">
            <Head />
          </g>
        </g>
      </g>
    </svg>
  );
}
