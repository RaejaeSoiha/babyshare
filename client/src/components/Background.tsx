import { useEffect, useRef } from "react";

type Particle = {
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

    const placeOnEdge = () => {
      const side = Math.floor(Math.random() * 4);
      const edgeDepth = 0.04 + Math.random() * 0.19;
      if (side === 0) return { x: Math.random() * width, y: height * edgeDepth };
      if (side === 1) return { x: width * (1 - edgeDepth), y: Math.random() * height };
      if (side === 2) return { x: Math.random() * width, y: height * (1 - edgeDepth) };
      return { x: width * edgeDepth, y: Math.random() * height };
    };

    const resize = () => {
      width = window.innerWidth;
      height = window.innerHeight;
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
        radius: 1.2 + Math.random() * 1.1,
        color: COLORS[Math.floor(Math.random() * COLORS.length)],
      });
    }

    const draw = () => {
      context.clearRect(0, 0, width, height);
      context.lineWidth = 0.55;

      particles.forEach((particle) => {
        particle.x += particle.vx;
        particle.y += particle.vy;
        if (particle.x < -8 || particle.x > width + 8) particle.vx *= -1;
        if (particle.y < -8 || particle.y > height + 8) particle.vy *= -1;

        context.beginPath();
        context.arc(particle.x, particle.y, particle.radius, 0, Math.PI * 2);
        context.fillStyle = particle.color;
        context.globalAlpha = 0.72;
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
            context.globalAlpha = (1 - distance / 230) * 0.18;
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
