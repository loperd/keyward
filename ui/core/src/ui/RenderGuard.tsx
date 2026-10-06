// A place the window cannot draw stays one place: the error is reported (the
// desktop app's log of actions listens for it) and a calm sheet stands where
// the window was, with the way back. Without this a single unknown field took
// the whole window down and left it blank and deaf. A failed place is tried
// again once the line has moved to another; a window that draws is never
// drawn anew for it (its sheets, their motion and its state carry on).
import { Component, type ReactNode } from "react";
import { t } from "../i18n";

type Props = { children: ReactNode; line: string; onBack: () => void };
/// `at`: the line the guard last saw, the one a failure stands at.
type State = { failed: boolean; at: string };

export class RenderGuard extends Component<Props, State> {
  override state: State = { failed: false, at: this.props.line };

  static getDerivedStateFromError(): Partial<State> {
    return { failed: true };
  }

  static getDerivedStateFromProps(props: Props, state: State): Partial<State> | null {
    if (props.line === state.at) return null;
    return { failed: false, at: props.line };
  }

  override componentDidCatch(error: unknown) {
    // `reportError` raises it as an uncaught error: the page's error listeners
    // (the log of actions) see it, and the console has its stack.
    reportError(error);
  }

  override render() {
    if (!this.state.failed) return this.props.children;
    return (
      <div className="kw-window kw-failed" role="alert">
        <h1>{t("error.title")}</h1>
        <p>{t("error.hint")}</p>
        <button type="button" className="kw-btn kw-solid" onClick={() => {
          this.setState({ failed: false });
          this.props.onBack();
        }}>
          {t("error.back")}
        </button>
      </div>
    );
  }
}
