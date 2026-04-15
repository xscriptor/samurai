import { DOCUMENT } from '@angular/common';
import { Inject, Injectable, signal } from '@angular/core';

export type ThemeClass = 'theme-dark' | 'theme-light';

@Injectable({
  providedIn: 'root'
})
export class ThemeService {
  private readonly themeStorageKey = 'samurai-theme';
  private readonly transitionClassName = 'theme-transitioning';
  private transitionTimeout: ReturnType<typeof setTimeout> | null = null;

  readonly currentTheme = signal<ThemeClass>('theme-dark');

  constructor(@Inject(DOCUMENT) private document: Document) {}

  initTheme(): void {
    const storedTheme = this.readStoredTheme();
    const bodyTheme = this.document.body.classList.contains('theme-light') ? 'theme-light' : 'theme-dark';

    this.applyTheme(storedTheme || bodyTheme, false);
  }

  toggleTheme(): void {
    const nextTheme: ThemeClass = this.currentTheme() === 'theme-dark' ? 'theme-light' : 'theme-dark';
    this.applyTheme(nextTheme, true);
  }

  nextThemeLabel(): string {
    return this.currentTheme() === 'theme-dark' ? 'LIGHT MODE' : 'DARK MODE';
  }

  nextThemeAriaLabel(): string {
    return this.currentTheme() === 'theme-dark' ? 'Switch to light theme' : 'Switch to dark theme';
  }

  private applyTheme(theme: ThemeClass, animate: boolean): void {
    this.currentTheme.set(theme);

    const bodyClassList = this.document.body.classList;

    if (animate) {
      this.enableThemeTransition(bodyClassList);
    }

    bodyClassList.remove('theme-dark', 'theme-light');
    bodyClassList.add(theme);

    localStorage.setItem(this.themeStorageKey, theme);
  }

  private enableThemeTransition(bodyClassList: DOMTokenList): void {
    bodyClassList.add(this.transitionClassName);

    if (this.transitionTimeout !== null) {
      clearTimeout(this.transitionTimeout);
    }

    this.transitionTimeout = setTimeout(() => {
      bodyClassList.remove(this.transitionClassName);
      this.transitionTimeout = null;
    }, 260);
  }

  private readStoredTheme(): ThemeClass | null {
    const storedTheme = localStorage.getItem(this.themeStorageKey);

    if (storedTheme === 'theme-dark' || storedTheme === 'theme-light') {
      return storedTheme;
    }

    return null;
  }
}
