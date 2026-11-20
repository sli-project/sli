/// <reference types="vite/client" />

type SliV4FixtureObjectPresentation = {
  initials: string;
  kind?: string;
  tags: Array<[string, string]>;
  route?: string;
};

type SliV4FixturePresentation = {
  defaultObjectSearch: string;
  defaultEventFilter: string;
  objects: Record<string, SliV4FixtureObjectPresentation>;
  workspaceProblems: Array<{
    id: string;
    tone: string;
    title: string;
    copy: string;
    meta: string[];
    href: string;
    icon: string;
    action: string;
  }>;
};

declare global {
  var __SLI_V4_FIXTURE_PRESENTATION__: SliV4FixturePresentation | undefined;
}

export {};
