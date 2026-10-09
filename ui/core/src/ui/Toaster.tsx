// The toasts drawn: a stack at the bottom of the window, each with the icon
// of its kind. A toast comes up and fades in; going, it fades and sinks, and
// is taken out once that has played.
import { t } from "../i18n";
import { Icon } from "./Icons";
import { useToasts, ToastKind, type Toasts } from "./toasts";

const ICON: Record<ToastKind, string> = { [ToastKind.Ok]: "check", [ToastKind.Error]: "state", [ToastKind.Copy]: "copy", [ToastKind.Info]: "info" };

export function Toaster({ toasts }: { toasts: Toasts }) {
  const list = useToasts(toasts);
  if (!list.length) return null;
  return (
    <div className="toasts">
      {list.map((x) => (
        <div
          key={x.id}
          className={`toast t-${x.kind}${x.leaving ? " leave" : ""}`}
          role={x.kind === ToastKind.Error ? "alert" : "status"}
          onClick={() => toasts.dismiss(x.id)}
          title={t("ui.toast.dismiss")}
          onAnimationEnd={(e) => {
            if (x.leaving && e.target === e.currentTarget) toasts.remove(x.id);
          }}
        >
          <Icon name={ICON[x.kind]} />
          <span>{x.text}</span>
        </div>
      ))}
    </div>
  );
}
