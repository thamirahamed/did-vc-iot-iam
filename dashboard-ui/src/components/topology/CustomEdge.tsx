import {
  BaseEdge,
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
  const color = data?.color || "#00dce5";
  const active = data?.active;
  const muted = data?.muted;

  return (
    <>
      <BaseEdge
        id={id}
        path={edgePath}
        style={{
          stroke: color,
          strokeWidth: active ? 3 : 2,
          strokeOpacity: muted ? 0.28 : active ? 1 : 0.72,
          strokeDasharray: data?.dashed ? "7 7" : undefined,
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
