import {
  BarChart3,
  RotateCcw,
  GitBranch,
  Network,
  ShieldAlert,
  Wallet,
} from "lucide-react";
import type { NavItem, PageKey } from "../types";
import iamLabLogo from "../iam_lab_logo.svg?raw";

const navItems: NavItem[] = [
  { key: "topology", label: "Live Topology", icon: Network },
  { key: "wallet", label: "Device Wallet", icon: Wallet },
  { key: "ledger", label: "Fabric Ledger Explorer", icon: GitBranch },
  { key: "security", label: "Security Scenarios", icon: ShieldAlert },
  { key: "performance", label: "Performance", icon: BarChart3 },
];

type SidebarProps = {
  activePage: PageKey;
  onNavigate: (page: PageKey) => void;
  disabled?: boolean;
  onCleanState: () => void;
};

export default function Sidebar({
  activePage,
  onNavigate,
  disabled,
  onCleanState,
}: SidebarProps) {
  return (
    <aside className="fixed inset-y-0 left-0 z-40 flex w-[220px] flex-col border-r border-line/40 bg-panel/95">
      <div className="border-b border-line/30 p-4">
        <div className="flex items-center gap-3">
          <div>
            <h1 className="text-base font-bold leading-tight text-cyan">IAM Lab</h1>
            <p className="font-mono text-[10px] uppercase text-muted">
              VC BASED IOT IAM
            </p>
          </div>
        </div>
      </div>
      <nav className="flex-1 space-y-1 overflow-y-auto p-3">
        {navItems.map((item) => {
          const Icon = item.icon;
          const active = activePage === item.key;
          return (
            <button
              key={item.key}
              type="button"
              onClick={() => onNavigate(item.key)}
              disabled={disabled}
              className={`flex w-full items-center gap-3 rounded px-3 py-2 text-left text-sm transition ${
                active
                  ? "border border-cyan/30 bg-cyan/10 text-cyan"
                  : "text-muted hover:bg-panel-strong hover:text-text"
              } disabled:cursor-wait disabled:opacity-50`}
            >
              <Icon size={18} />
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>
      <div className="border-t border-line/30 p-3">
        <button
          type="button"
          onClick={onCleanState}
          disabled={disabled}
          className="mb-3 flex w-full items-center gap-2 rounded border border-danger/45 bg-danger/10 px-3 py-2 text-left font-mono text-[11px] uppercase text-danger transition hover:bg-danger/15 disabled:cursor-wait disabled:opacity-50"
        >
          <RotateCcw size={15} />
          Reset Session
        </button>
        <div className="font-mono text-[10px] uppercase text-muted text-center">
          Thamir Ahamed | CB012828
        </div>
      </div>
    </aside>
  );
}
