import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface TicketReply {
  ID?: number;
  ticket_id?: number;
  author_name?: string;
  author_role?: string;
  message: string;
  CreatedAt?: string;
}

export interface Ticket {
  ID?: number;
  title: string;
  description: string;
  status?: string;
  priority: string;
  customer?: any;
  attachment_path?: string;
  assigned_to?: string;
  assigned_user_id?: number;
  phone_number?: string;
  replies?: TicketReply[];
  showReplies?: boolean;
  repliesLoaded?: boolean;
  newReplyMessage?: string;
}

export interface AgentUser {
  id?: number;
  name: string;
  email: string;
}

export interface ActivityLog {
  ID: number;
  user_id: number;
  user_name: string;
  role: string;
  action: string;
  details: string;
  ip_address: string;
  CreatedAt: string;
}

@Injectable({
  providedIn: 'root'
})
export class TicketService {
  private apiUrl = '/api/tickets';
  private customerTicketsUrl = '/api/customer/tickets';
  private agentLoginUrl = '/api/Admin/login';
  private agentEmailLoginUrl = '/api/Admin/login-by-email';
  private customerLoginUrl = '/api/customer/login';
  private customerRegisterUrl = '/api/customer/register';
  private agentsUrl = '/api/agents';

  constructor(private http: HttpClient) { }

  getTickets(): Observable<Ticket[]> {
    const token = localStorage.getItem('agentToken');
    const headers = token ? new HttpHeaders({ Authorization: `Bearer ${token}` }) : undefined;

    return this.http.get<Ticket[]>(this.apiUrl, { headers });
  }

  createTicket(payload: FormData): Observable<Ticket> {
    const customerToken = localStorage.getItem('customerToken');
    const headers = customerToken ? new HttpHeaders({ Authorization: `Bearer ${customerToken}` }) : undefined;

    return this.http.post<Ticket>(this.apiUrl, payload, { headers });
  }

  assignTicket(id: number): Observable<Ticket> {
    const token = localStorage.getItem('agentToken');
    const headers = token ? new HttpHeaders({ Authorization: `Bearer ${token}` }) : undefined;

    return this.http.put<Ticket>(`${this.apiUrl}/${id}/assign`, {}, { headers });
  }

  getReplies(ticketId: number): Observable<TicketReply[]> {
    return this.http.get<TicketReply[]>(`${this.apiUrl}/${ticketId}/replies`);
  }

  addReply(ticketId: number, message: string): Observable<TicketReply> {
    const token = localStorage.getItem('agentToken');
    const headers = token ? new HttpHeaders({ Authorization: `Bearer ${token}` }) : undefined;

    return this.http.post<TicketReply>(`${this.apiUrl}/${ticketId}/replies`, { message }, { headers });
  }

  releaseTicket(id: number): Observable<Ticket> {
    const token = localStorage.getItem('agentToken');
    const headers = token ? new HttpHeaders({ Authorization: `Bearer ${token}` }) : undefined;

    return this.http.put<Ticket>(`${this.apiUrl}/${id}/release`, {}, { headers });
  }

  loginAgent(email: string, password: string): Observable<{ token: string; name: string }> {
    return this.http.post<{ token: string; name: string }>(this.agentLoginUrl, {
      email,
      password
    });
  }

  loginAgentWithEmail(email: string): Observable<{ token: string; name: string }> {
    return this.http.post<{ token: string; name: string }>(this.agentEmailLoginUrl, {
      email
    });
  }

  loginCustomer(email: string, password: string): Observable<{ token: string; name: string; role: string }> {
    return this.http.post<{ token: string; name: string; role: string }>(this.customerLoginUrl, {
      email,
      password
    });
  }

  registerCustomer(name: string, email: string, password: string): Observable<{ token: string; name: string; role: string }> {
    return this.http.post<{ token: string; name: string; role: string }>(this.customerRegisterUrl, {
      name,
      email,
      password
    });
  }

  getCustomerTickets(): Observable<Ticket[]> {
    const token = localStorage.getItem('customerToken');
    const headers = token ? new HttpHeaders({ Authorization: `Bearer ${token}` }) : undefined;

    return this.http.get<Ticket[]>(this.customerTicketsUrl, { headers });
  }

  deleteCustomerTicket(id: number): Observable<void> {
    const token = localStorage.getItem('customerToken');
    const headers = token ? new HttpHeaders({ Authorization: `Bearer ${token}` }) : undefined;

    return this.http.delete<void>(`${this.customerTicketsUrl}/${id}`, { headers });
  }

  completeTicket(id: number): Observable<Ticket> {
    const token = localStorage.getItem('agentToken');
    const headers = token ? new HttpHeaders({ Authorization: `Bearer ${token}` }) : undefined;

    return this.http.put<Ticket>(`${this.apiUrl}/${id}/complete`, {}, { headers });
  }

  addCustomerReply(ticketId: number, message: string): Observable<TicketReply> {
    const token = localStorage.getItem('customerToken');
    const headers = token ? new HttpHeaders({ Authorization: `Bearer ${token}` }) : undefined;

    return this.http.post<TicketReply>(`${this.apiUrl}/${ticketId}/replies`, { message }, { headers });
  }

  getAgents(): Observable<AgentUser[]> {
    return this.http.get<AgentUser[]>(this.agentsUrl);
  }

  getLogs(): Observable<ActivityLog[]> {
    const token = localStorage.getItem('agentToken');
    const headers = token ? new HttpHeaders({ Authorization: `Bearer ${token}` }) : undefined;
    return this.http.get<ActivityLog[]>('/api/admin/logs', { headers });
  }

  clearAllTickets(): Observable<void> {
    const token = localStorage.getItem('agentToken');
    const headers = token ? new HttpHeaders({ Authorization: `Bearer ${token}` }) : undefined;

    return this.http.delete<void>(this.apiUrl, { headers });
  }

  deleteTicket(id: number): Observable<void> {
    const token = localStorage.getItem('agentToken');
    const headers = token ? new HttpHeaders({ Authorization: `Bearer ${token}` }) : undefined;

    return this.http.delete<void>(`${this.apiUrl}/${id}`, { headers });
  }
}
