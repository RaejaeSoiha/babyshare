import { useEffect, useRef } from "react";

type Particle = {
  alpha: number;
  color: string;
  radius: number;
  vx: number;
  vy: number;
  x: number;
  y: number;
};

const COLORS = ["#49b8ff", "#55d8ff", "#1f8cff", "#e9b95b"];

// A deliberately quiet particle network, concentrated around the screen's edges.
export default function Background() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const rafRef = useRef<number | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const context = canvas?.getContext("2d");
    if (!canvas || !context) return;

    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const particles: Particle[] = [];
    let width = 0;
    let height = 0;
    let lastFrameTime = 0;
    let mobileFrameInterval = 0;

    const placeOnEdge = () => {
      // Give the lower corners a little more presence without crowding the center.
      if (Math.random() < 0.3) {
        const onLeft = Math.random() < 0.5;
        return {
          x: width * (onLeft ? 0.03 + Math.random() * 0.15 : 0.82 + Math.random() * 0.15),
          y: height * (0.76 + Math.random() * 0.2),
          lowerCorner: true,
        };
      }
      const side = Math.floor(Math.random() * 4);
      const edgeDepth = 0.04 + Math.random() * 0.19;
      if (side === 0) return { x: Math.random() * width, y: height * edgeDepth, lowerCorner: false };
      if (side === 1) return { x: width * (1 - edgeDepth), y: Math.random() * height, lowerCorner: false };
      if (side === 2) return { x: Math.random() * width, y: height * (1 - edgeDepth), lowerCorner: false };
      return { x: width * edgeDepth, y: Math.random() * height, lowerCorner: false };
    };

    const resize = () => {
      width = window.innerWidth;
      height = window.innerHeight;
      mobileFrameInterval = width < 680 ? 33 : 0;
      const pixelRatio = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.round(width * pixelRatio);
      canvas.height = Math.round(height * pixelRatio);
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      context.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
    };

    resize();
    const particleCount = window.innerWidth < 680 ? 8 : 18;
    for (let index = 0; index < particleCount; index += 1) {
      const position = placeOnEdge();
      particles.push({
        ...position,
        vx: (Math.random() - 0.5) * 0.18,
        vy: (Math.random() - 0.5) * 0.18,
        alpha: position.lowerCorner ? 0.78 : 0.64,
        radius: position.lowerCorner ? 1.55 + Math.random() * 0.85 : 1.1 + Math.random() * 0.95,
        color: COLORS[Math.floor(Math.random() * COLORS.length)],
      });
    }

    const drawGrid = (timestamp: number) => {
      const spacing = width < 680 ? 92 : 120;
      const horizontalShift = reduceMotion ? 0 : (timestamp * 0.005) % spacing;
      const verticalShift = reduceMotion ? 0 : (timestamp * 0.0035) % spacing;
      context.lineWidth = 0.55;

      // A low-contrast network grid creates the row-and-column structure without obscuring content.
      for (let x = -spacing + horizontalShift; x <= width + spacing; x += spacing) {
        const pulse = (Math.sin((x / spacing) + (timestamp / 3_600)) + 1) * 0.5;
        context.beginPath();
        context.moveTo(x, 0);
        context.lineTo(x, height);
        context.strokeStyle = "#4bbfff";
        context.globalAlpha = 0.13 + pulse * 0.07;
        context.stroke();
      }

      for (let y = -spacing + verticalShift; y <= height + spacing; y += spacing) {
        const pulse = (Math.sin((y / spacing) - (timestamp / 4_200)) + 1) * 0.5;
        context.beginPath();
        context.moveTo(0, y);
        context.lineTo(width, y);
        context.strokeStyle = "#61d0ff";
        context.globalAlpha = 0.11 + pulse * 0.06;
        context.stroke();
      }

      if (!reduceMotion) {
        const scanX = ((timestamp * 0.018) % (width + spacing * 2)) - spacing;
        const scanY = ((timestamp * 0.012) % (height + spacing * 2)) - spacing;
        context.lineWidth = 0.9;
        context.beginPath();
        context.moveTo(scanX, 0);
        context.lineTo(scanX, height);
        context.strokeStyle = "#54cfff";
        context.globalAlpha = 0.34;
        context.stroke();
        context.beginPath();
        context.moveTo(0, scanY);
        context.lineTo(width, scanY);
        context.strokeStyle = "#68d9ff";
        context.globalAlpha = 0.27;
        context.stroke();
      }
    };

    const draw = (timestamp = 0) => {
      if (mobileFrameInterval && timestamp - lastFrameTime < mobileFrameInterval) {
        rafRef.current = requestAnimationFrame(draw);
        return;
      }
      lastFrameTime = timestamp;
      context.clearRect(0, 0, width, height);
      drawGrid(timestamp);
      context.lineWidth = 0.55;

      particles.forEach((particle) => {
        particle.x += particle.vx;
        particle.y += particle.vy;
        if (particle.x < -8 || particle.x > width + 8) particle.vx *= -1;
        if (particle.y < -8 || particle.y > height + 8) particle.vy *= -1;

        context.beginPath();
        context.arc(particle.x, particle.y, particle.radius, 0, Math.PI * 2);
        context.fillStyle = particle.color;
        context.globalAlpha = particle.alpha;
        context.fill();
      });

      for (let first = 0; first < particles.length; first += 1) {
        for (let second = first + 1; second < particles.length; second += 1) {
          const a = particles[first];
          const b = particles[second];
          const distance = Math.hypot(a.x - b.x, a.y - b.y);
          if (distance < 230) {
            context.beginPath();
            context.moveTo(a.x, a.y);
            context.lineTo(b.x, b.y);
            context.strokeStyle = "#58cfff";
            context.globalAlpha = (1 - distance / 230) * 0.16;
            context.stroke();
          }
        }
      }
      context.globalAlpha = 1;
      if (!reduceMotion) rafRef.current = requestAnimationFrame(draw);
    };

    draw();
    window.addEventListener("resize", resize);
    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
      window.removeEventListener("resize", resize);
    };
  }, []);

  return (
    <>
      <canvas ref={canvasRef} className="bg-canvas" aria-hidden="true" />
      <div className="starfield" aria-hidden="true" />
      <div className="home-glow" aria-hidden="true" />
    </>
  );
}
