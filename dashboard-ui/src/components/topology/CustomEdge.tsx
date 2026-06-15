import {
  getBezierPath,
  type EdgeProps,
} from "reactflow";

export type CustomEdgeData = {
  color: string;
  dashed?: boolean;
  active?: boolean;
  muted?: boolean;
  name: string;
  tooltip: string;
};

export default function CustomEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  data,
}: EdgeProps<CustomEdgeData>) {
  const [edgePath] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  });
  const color = data?.color || "#00D8FF";
  const active = data?.active;
  const muted = data?.muted;
  const dashLength = 8;
  const dashGap = 8;

  return (
    <>
      <path
        id={id}
        d={edgePath}
        fill="none"
        className="react-flow__edge-path topology-animated-edge"
        style={{
          stroke: color,
          strokeWidth: active ? 3 : 2,
          strokeOpacity: muted ? 0.28 : active ? 1 : 0.72,
          strokeDasharray: `${dashLength} ${dashGap}`,
          strokeDashoffset: dashLength + dashGap,
          filter: active ? `drop-shadow(0 0 8px ${color})` : undefined,
        }}
      />
      <path
        d={edgePath}
        fill="none"
        stroke="transparent"
        strokeWidth={18}
        className="react-flow__edge-interaction"
      />
    </>
  );
}
