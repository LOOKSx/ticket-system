import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface TicketReply {
  ID?: number;
  ticket_id?: number;
  author_name?: string;
  author_role?: string;
  message: string;
  attachment_path?: string;
  attachment_thumb_path?: string;
  CreatedAt?: string;
}

export interface Ticket {
  ID?: number;
  CreatedAt?: string;
  title: string;
  description: string;
  status?: string;
  priority: string;
  due_at?: string;
  escalation_level?: number;
  last_escalated_at?: string;
  tags?: string;
  customer?: any;
  attachment_path?: string;
  attachment_thumb_path?: string;
  attachments?: Array<{ path: string; thumb_path?: string }>;
  assigned_to?: string;
  assigned_user_id?: number;
  phone_number?: string;
  replies?: TicketReply[];
  showReplies?: boolean;
  repliesLoaded?: boolean;
  newReplyMessage?: string;
  newReplyAttachment?: File | null;
  tagsDraft?: string;
  tagsEditing?: boolean;
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

  addReplyWithAttachment(ticketId: number, message: string, attachment: File | null): Observable<TicketReply> {
    const token = localStorage.getItem('agentToken');
    const headers = token ? new HttpHeaders({ Authorization: `Bearer ${token}` }) : undefined;
    const prepare = async () => {
      const formData = new FormData();
      formData.append('message', message || '');
      if (attachment && /^image\//i.test(attachment.type)) {
        const compressed = await this.compressImage(attachment, 1600, 0.85).catch(() => attachment);
        formData.append('attachment', compressed);
      } else if (attachment) {
        formData.append('attachment', attachment);
      }
      return formData;
    };
    return new Observable<TicketReply>((subscriber) => {
      prepare()
        .then((formData) => {
          this.http.post<TicketReply>(`${this.apiUrl}/${ticketId}/replies`, formData, { headers }).subscribe({
            next: (v) => subscriber.next(v),
            error: (e) => subscriber.error(e),
            complete: () => subscriber.complete()
          });
        })
        .catch((err) => subscriber.error(err));
    });
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

  updateTicketTags(id: number, tags: string[]): Observable<Ticket> {
    const token = localStorage.getItem('agentToken');
    const headers = token ? new HttpHeaders({ Authorization: `Bearer ${token}` }) : undefined;
    return this.http.put<Ticket>(`${this.apiUrl}/${id}/tags`, { tags }, { headers });
  }

  private compressImage(file: File, maxDim: number, quality: number): Promise<File> {
    return new Promise<File>((resolve, reject) => {
      const img = new Image();
      const reader = new FileReader();
      reader.onload = () => {
        img.onload = () => {
          const canvas = document.createElement('canvas');
          let { width, height } = img;
          if (width > height && width > maxDim) {
            height = Math.round((height * maxDim) / width);
            width = maxDim;
          } else if (height > maxDim) {
            width = Math.round((width * maxDim) / height);
            height = maxDim;
          }
          canvas.width = width;
          canvas.height = height;
          const ctx = canvas.getContext('2d');
          if (!ctx) {
            reject(new Error('Canvas not supported'));
            return;
          }
          ctx.drawImage(img, 0, 0, width, height);
          canvas.toBlob(
            (blob) => {
              if (!blob) {
                reject(new Error('Failed to compress image'));
                return;
              }
              const ext = file.type.includes('png') ? 'png' : 'jpeg';
              const name =
                file.name.replace(/\\.(png|jpg|jpeg|webp)$/i, '') + (ext === 'png' ? '.png' : '.jpg');
              resolve(new File([blob], name, { type: `image/${ext}` }));
            },
            file.type.includes('png') ? 'image/png' : 'image/jpeg',
            quality
          );
        };
        img.onerror = () => reject(new Error('Image load error'));
        img.src = reader.result as string;
      };
      reader.onerror = () => reject(reader.error || new Error('File read error'));
      reader.readAsDataURL(file);
    });
  }
}
