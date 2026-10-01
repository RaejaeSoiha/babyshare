import { useEffect, useState } from "react";

export type ResponsiveViewport = {
  bottom: number;
  height: number;
  isCompact: boolean;
  left: number;
  width: number;
};

function measureViewport(): ResponsiveViewport {
  const visualViewport = window.visualViewport;
  const viewportWidth = visualViewport?.width ?? window.innerWidth;
  const viewportHeight = visualViewport?.height ?? window.innerHeight;
  const viewportTop = visualViewport?.offsetTop ?? 0;
  const viewportLeft = visualViewport?.offsetLeft ?? 0;
  const layoutHeight = Math.max(window.innerHeight, document.documentElement.clientHeight);
  const hiddenBelowViewport = Math.max(0, layoutHeight - viewportHeight - viewportTop);

  return {
    bottom: Math.round(hiddenBelowViewport + 12),
    height: Math.round(Math.min(520, Math.max(160, viewportHeight - 24))),
    isCompact: viewportWidth <= 680,
    left: Math.round(viewportLeft + 12),
    width: Math.round(Math.max(0, viewportWidth - 24)),
  };
}

// Fixed panels need the visual viewport rather than the page's layout viewport
// so they remain usable when a mobile keyboard or browser chrome is visible.
export function useResponsiveViewport() {
  const [viewport, setViewport] = useState<ResponsiveViewport | null>(() => (
    typeof window === "undefined" ? null : measureViewport()
  ));

  useEffect(() => {
    const update = () => setViewport(measureViewport());
    const frame = window.requestAnimationFrame(update);
    window.addEventListener("resize", update);
    window.visualViewport?.addEventListener("resize", update);
    window.visualViewport?.addEventListener("scroll", update);
    return () => {
      window.cancelAnimationFrame(frame);
      window.removeEventListener("resize", update);
      window.visualViewport?.removeEventListener("resize", update);
      window.visualViewport?.removeEventListener("scroll", update);
    };
  }, []);

  return viewport;
}
