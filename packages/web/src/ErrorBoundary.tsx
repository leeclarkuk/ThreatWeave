import { Component, type ReactNode } from 'react';

/** A render fault must not leave a blank page. Edits are autosaved, so reloading loses nothing that was saved. */
export class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) { return { error }; }
  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="home" role="alert">
        <h1>Something went wrong in the interface</h1>
        <p className="lede">Your project is saved on disk as of your last edit. Reload to continue. If this repeats, the details below help a bug report (they contain no project text).</p>
        <pre className="runlog">{this.state.error.name}: {this.state.error.message}</pre>
        <p><button className="primary" onClick={() => window.location.reload()}>Reload</button> <a href="#/" onClick={() => setTimeout(() => window.location.reload(), 0)}>Back to projects</a></p>
      </div>
    );
  }
}
