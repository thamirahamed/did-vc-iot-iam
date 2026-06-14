import type { ReactNode } from "react";
import type { PageKey, ServiceHealth } from "../types";
import Sidebar from "./Sidebar";
import StatusBar from "./StatusBar";

type LayoutProps = {
  activePage: PageKey;
  onNavigate: (page: PageKey) => void;
  health: {
    issuer: ServiceHealth;
    verifier: ServiceHealth;
    fabricAdapter: ServiceHealth;
  };
  controlsDisabled?: boolean;
  onCleanState: () => void;
  children: ReactNode;
};

export default function Layout({
  activePage,
  onNavigate,
  health,
  controlsDisabled,
  onCleanState,
  children,
}: LayoutProps) {
  return (
    <div className="min-h-screen bg-background text-text">
      <Sidebar
        activePage={activePage}
        onNavigate={onNavigate}
        disabled={controlsDisabled}
        onCleanState={onCleanState}
      />
      <div className="ml-[220px] min-h-screen w-[calc(100vw-220px)] max-w-[calc(100vw-220px)] overflow-x-hidden">
        <StatusBar
          issuer={health.issuer}
          verifier={health.verifier}
          fabricAdapter={health.fabricAdapter}
        />
        <main className="w-full">{children}</main>
      </div>
    </div>
  );
}
