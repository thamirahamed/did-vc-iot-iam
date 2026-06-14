type FlowTooltipProps = {
  x: number;
  y: number;
  title: string;
  body: string;
  color: string;
};

export default function FlowTooltip({ x, y, title, body, color }: FlowTooltipProps) {
  return (
    <div
      className="pointer-events-none fixed z-50 w-80 rounded border border-line/50 bg-panel/95 p-3 shadow-glow backdrop-blur"
      style={{ left: x + 14, top: y + 14 }}
    >
      <div className="font-mono text-xs uppercase" style={{ color }}>
        {title}
      </div>
      <p className="mt-2 text-sm leading-5 text-muted">{body}</p>
    </div>
  );
}
