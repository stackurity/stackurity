import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { ARTICLES, ARTICLE_BY_ID } from "../help/articles";
import { RenderBlock } from "../help/render";
import { articleText, SECTIONS } from "../help/types";
import { EmptyState, PageHeader } from "../components/ui";

const SEARCH_INDEX = ARTICLES.map((a) => ({ id: a.id, text: articleText(a) }));

export function HelpPage() {
  const { topic } = useParams();
  const navigate = useNavigate();
  const [q, setQ] = useState("");
  const article = ARTICLE_BY_ID[topic ?? "what-is-stackurity"];

  const matches = useMemo(() => {
    const words = q.toLowerCase().split(/\s+/).filter(Boolean);
    if (words.length === 0) return null;
    return new Set(SEARCH_INDEX.filter((x) => words.every((w) => x.text.includes(w))).map((x) => x.id));
  }, [q]);

  useEffect(() => {
    document.getElementById("main")?.scrollTo?.(0, 0);
    window.scrollTo(0, 0);
  }, [topic]);

  return (
    <>
      <PageHeader title="Help" sub="How each part of Stackurity works, where to find it, and step-by-step guides." />
      <div className="help-layout">
        <nav className="help-nav" aria-label="Help topics">
          <div className="field">
            <label htmlFor="help-q">Search help</label>
            <input
              id="help-q"
              type="search"
              placeholder="e.g. add server, policy, Slack"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && matches && matches.size > 0) navigate(`/help/${[...matches][0]}`);
              }}
            />
          </div>
          {matches && <p className="small muted" role="status">{matches.size === 0 ? "No topics match." : `${matches.size} matching topic${matches.size === 1 ? "" : "s"}`}</p>}
          {SECTIONS.map((section) => {
            const items = ARTICLES.filter((a) => a.section === section && (!matches || matches.has(a.id)));
            if (items.length === 0) return null;
            return (
              <div key={section} className="help-nav-section">
                <p className="h-sm">{section}</p>
                <ul>
                  {items.map((a) => (
                    <li key={a.id}>
                      <Link to={`/help/${a.id}`} className={a.id === article?.id ? "active" : undefined} aria-current={a.id === article?.id ? "page" : undefined}>
                        {a.title}
                      </Link>
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
        </nav>
        <article className="help-article card" aria-labelledby="help-title">
          {!article ? (
            <EmptyState title="No such help topic">
              <p>
                Pick a topic on the left, or start with <Link to="/help/what-is-stackurity">What Stackurity does</Link>.
              </p>
            </EmptyState>
          ) : (
            <>
              <p className="h-sm">{article.section}</p>
              <h2 id="help-title" className="help-title">
                {article.title}
              </h2>
              <p className="help-summary">{article.summary}</p>
              {article.where && (
                <p className="help-where">
                  <strong>Where to find it:</strong> Menu ▸ {article.where.join(" ▸ ")}
                </p>
              )}
              {article.body.map((b, i) => (
                <RenderBlock key={i} b={b} />
              ))}
            </>
          )}
        </article>
      </div>
    </>
  );
}
