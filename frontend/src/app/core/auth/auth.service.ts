import { Injectable, inject, signal } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable, catchError, of, switchMap, tap } from 'rxjs';
import { ApiConfigService } from '../api/api-config.service';
import { environment } from '../../../environments/environment';

export interface LoginPayload {
  username: string;
  password: string;
}

export interface LoginResponse {
  access_token: string;
  token_type?: string;
  expires_in?: number;
}

export interface CurrentUser {
  id: number;
  username: string;
  email: string;
  role: 'admin' | 'operator' | 'viewer' | string;
  is_active: boolean;
  created_at: string;
}

const TOKEN_STORAGE_KEY = 'samurai-auth-token';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly http = inject(HttpClient);
  private readonly api = inject(ApiConfigService);

  readonly token = signal<string | null>(this.readStoredToken());
  readonly isAuthenticated = signal<boolean>(!!this.readStoredToken());
  readonly currentUser = signal<CurrentUser | null>(null);

  get authEnabled(): boolean {
    return environment.authEnabled;
  }

  login(payload: LoginPayload): Observable<LoginResponse> {
    const body = new URLSearchParams();
    body.set('username', payload.username);
    body.set('password', payload.password);

    const headers = new HttpHeaders({ 'Content-Type': 'application/x-www-form-urlencoded' });

    return this.http
      .post<LoginResponse>(this.api.http('/api/auth/login'), body.toString(), { headers })
      .pipe(
        tap((response) => this.setToken(response.access_token)),
        switchMap((response) =>
          this.fetchCurrentUser().pipe(
            catchError(() => of(null)),
            tap(() => undefined),
            switchMap(() => of(response))
          )
        )
      );
  }

  fetchCurrentUser(): Observable<CurrentUser | null> {
    if (!this.token()) {
      return of(null);
    }
    return this.http.get<CurrentUser>(this.api.http('/api/auth/me')).pipe(
      tap((user) => this.currentUser.set(user)),
      catchError(() => {
        this.clearToken();
        return of(null);
      })
    );
  }

  logout(): void {
    this.clearToken();
  }

  getToken(): string | null {
    return this.token();
  }

  private setToken(token: string): void {
    try {
      localStorage.setItem(TOKEN_STORAGE_KEY, token);
    } catch {
      // Storage unavailable in restricted contexts; degrade silently.
    }
    this.token.set(token);
    this.isAuthenticated.set(true);
  }

  private clearToken(): void {
    try {
      localStorage.removeItem(TOKEN_STORAGE_KEY);
    } catch {
      // Storage unavailable in restricted contexts; degrade silently.
    }
    this.token.set(null);
    this.isAuthenticated.set(false);
    this.currentUser.set(null);
  }

  private readStoredToken(): string | null {
    try {
      return localStorage.getItem(TOKEN_STORAGE_KEY);
    } catch {
      return null;
    }
  }
}
