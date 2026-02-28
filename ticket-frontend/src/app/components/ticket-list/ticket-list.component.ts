import { Component, Input, OnInit, Output, EventEmitter } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { TicketService, Ticket, TicketReply, AgentUser } from '../../services/ticket.service';

@Component({
  selector: 'app-ticket-list',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './ticket-list.component.html',
  styleUrls: ['./ticket-list.component.css']
})
export class TicketListComponent implements OnInit {
  @Input() tickets: Ticket[] = [];
  @Output() resetRequested = new EventEmitter<void>();
  @Output() ticketUpdated = new EventEmitter<Ticket>();

  currentAgentName = '';
  agentEmail = '';
  password = '';
  isLoggedIn = false;
  loginError = '';

  agents: AgentUser[] = [];

  confirmVisible = false;
  confirmMessage = '';
  confirmShowCancel = true;
  private pendingConfirmAction: (() => void) | null = null;

  detailVisible = false;
  detailTicket: Ticket | null = null;

  activeCategory: 'all' | 'open' | 'in_progress' | 'closed' | 'unassigned' = 'all';

  constructor(private ticketService: TicketService) {}

  ngOnInit(): void {
    this.syncLoginStateFromStorage();
    if (!this.isLoggedIn) {
      this.tryAutoLoginFromQuery();
    }
    this.loadAgents();
  }

  refreshLoginFromStorage(): void {
    this.syncLoginStateFromStorage();
  }

  private syncLoginStateFromStorage(): void {
    const storedName = localStorage.getItem('agentName');
    const token = localStorage.getItem('agentToken');
    if (storedName && token) {
      this.currentAgentName = storedName;
      this.isLoggedIn = true;
    } else {
      this.currentAgentName = '';
      this.isLoggedIn = false;
    }
    this.loginError = '';
  }

  getStatusLabel(status?: string): string {
    if (!status) {
      return 'ไม่ระบุสถานะ';
    }
    switch (status.toLowerCase()) {
      case 'open':
        return 'ใหม่';
      case 'in_progress':
        return 'กำลังดำเนินการ';
      case 'closed':
        return 'ปิดงานแล้ว';
      default:
        return status;
    }
  }

  getPriorityLabel(priority?: string): string {
    if (!priority) {
      return 'ไม่ระบุความเร่งด่วน';
    }
    switch (priority.toLowerCase()) {
      case 'low':
        return 'ต่ำ';
      case 'medium':
        return 'ปานกลาง';
      case 'high':
        return 'สูง';
      default:
        return priority;
    }
  }

  isAdmin(role: string | undefined): boolean {
    return role ? role.toLowerCase() === 'admin' : false;
  }

  getAgentTickets(): Ticket[] {
    if (!this.currentAgentName) {
      return [];
    }
    return this.tickets.filter(t => t.assigned_to === this.currentAgentName);
  }

  countByStatus(status: 'open' | 'in_progress' | 'closed'): number {
    const target = status.toLowerCase();
    return this.tickets.filter(
      t => (t.status || '').toLowerCase() === target
    ).length;
  }

  countUnassigned(): number {
    return this.tickets.filter(t => !t.assigned_to).length;
  }

  getCategoryTickets(): Ticket[] {
    switch (this.activeCategory) {
      case 'open':
        return this.tickets.filter(t => (t.status || '').toLowerCase() === 'open');
      case 'in_progress':
        return this.tickets.filter(t => (t.status || '').toLowerCase() === 'in_progress');
      case 'closed':
        return this.tickets.filter(t => (t.status || '').toLowerCase() === 'closed');
      case 'unassigned':
        return this.tickets.filter(t => !t.assigned_to);
      default:
        return this.tickets;
    }
  }

  login(): void {
    this.loginError = '';
    if (!this.agentEmail || !this.password) {
      this.loginError = 'กรุณากรอกอีเมลและรหัสผ่าน';
      return;
    }

    this.ticketService.loginAgent(this.agentEmail, this.password).subscribe({
      next: (res) => {
        localStorage.setItem('agentToken', res.token);
        localStorage.setItem('agentName', res.name);
        this.currentAgentName = res.name;
        this.isLoggedIn = true;
        this.password = '';
        this.loginError = '';
      },
      error: (err) => {
        console.error('Agent login failed', err);
        this.loginError = 'อีเมลหรือรหัสผ่านไม่ถูกต้อง';
      }
    });
  }

  logout(): void {
    localStorage.removeItem('agentToken');
    localStorage.removeItem('agentName');
    this.syncLoginStateFromStorage();
    this.agentEmail = '';
    this.password = '';
  }

  requestReset(): void {
    this.resetRequested.emit();
  }

  clearAllTickets(): void {
    if (!this.isLoggedIn) {
      this.openInfo('กรุณาเข้าสู่ระบบเจ้าหน้าที่ก่อน');
      return;
    }
    this.openConfirm('ยืนยันว่าคุณต้องการล้างทิกเก็ตทั้งหมดออกจากระบบหรือไม่? การลบนี้ไม่สามารถย้อนกลับได้', () => {
      this.ticketService.clearAllTickets().subscribe({
        next: () => {
          this.resetRequested.emit();
          this.openInfo('ล้างทิกเก็ตทั้งหมดเรียบร้อยแล้ว');
        },
        error: (err) => {
          console.error('Error clearing tickets', err);
          this.openInfo('ไม่สามารถล้างทิกเก็ตได้ กรุณาลองใหม่ หรือตรวจสอบการเชื่อมต่อเซิร์ฟเวอร์');
        }
      });
    });
  }

  deleteTicket(ticket: Ticket): void {
    if (!ticket.ID) {
      return;
    }
    if (!this.isLoggedIn) {
      this.openInfo('กรุณาเข้าสู่ระบบเจ้าหน้าที่ก่อน');
      return;
    }
    this.openConfirm('ยืนยันว่าคุณต้องการลบทิกเก็ตนี้หรือไม่? การลบนี้ไม่สามารถย้อนกลับได้', () => {
      this.ticketService.deleteTicket(ticket.ID as number).subscribe({
        next: () => {
          this.tickets = this.tickets.filter(t => t.ID !== ticket.ID);
          this.openInfo(`ลบทิกเก็ต #${ticket.ID} เรียบร้อยแล้ว`);
        },
        error: (err) => {
          console.error('Error deleting ticket', err);
          this.openInfo('ไม่สามารถลบทิกเก็ตได้ กรุณาลองใหม่ หรือตรวจสอบการเชื่อมต่อเซิร์ฟเวอร์');
        }
      });
    });
  }

  private openConfirm(message: string, action: () => void): void {
    this.confirmMessage = message;
    this.confirmShowCancel = true;
    this.pendingConfirmAction = action;
    this.confirmVisible = true;
  }

  private openInfo(message: string): void {
    this.confirmMessage = message;
    this.confirmShowCancel = false;
    this.pendingConfirmAction = null;
    this.confirmVisible = true;
  }

  confirmYes(): void {
    if (this.pendingConfirmAction) {
      const action = this.pendingConfirmAction;
      this.pendingConfirmAction = null;
      this.confirmVisible = false;
      action();
      return;
    }
    this.confirmVisible = false;
  }

  confirmNo(): void {
    this.confirmVisible = false;
    this.pendingConfirmAction = null;
  }

  private tryAutoLoginFromQuery(): void {
    const search = window.location.search;
    if (!search) {
      return;
    }
    const params = new URLSearchParams(search);
    const email = params.get('agentEmail') || params.get('agent_email');
    if (!email) {
      return;
    }
    this.agentEmail = email;
    this.loginError = '';
    this.ticketService.loginAgentWithEmail(email).subscribe({
      next: (res) => {
        localStorage.setItem('agentToken', res.token);
        localStorage.setItem('agentName', res.name);
        this.currentAgentName = res.name;
        this.isLoggedIn = true;
      },
      error: (err) => {
        console.error('Agent auto login failed', err);
        this.loginError = 'ไม่สามารถเข้าสู่ระบบเจ้าหน้าที่อัตโนมัติได้';
      }
    });
  }

  private loadAgents(): void {
    this.ticketService.getAgents().subscribe({
      next: (agents) => {
        this.agents = agents;
      },
      error: (err) => {
        console.error('Failed to load agents', err);
      }
    });
  }

  assignTicket(ticket: Ticket): void {
    if (!ticket.ID) {
      return;
    }
    if (!this.isLoggedIn) {
      this.openInfo('กรุณาเข้าสู่ระบบเจ้าหน้าที่ก่อน');
      return;
    }
    this.ticketService.assignTicket(ticket.ID).subscribe({
      next: (updatedTicket) => {
        const index = this.tickets.findIndex(t => t.ID === updatedTicket.ID);
        if (index !== -1) {
          this.tickets[index] = updatedTicket;
        }
      },
      error: (err) => {
        console.error('Error assigning ticket', err);
        this.openInfo('ไม่สามารถรับทิกเก็ตได้ กรุณาลองใหม่ หรือตรวจสอบการเชื่อมต่อเซิร์ฟเวอร์');
      }
    });
  }

  openDetail(ticket: Ticket): void {
    this.detailTicket = ticket;
    this.detailVisible = true;
  }

  closeDetail(): void {
    this.detailVisible = false;
    this.detailTicket = null;
  }


  releaseTicket(ticket: Ticket): void {
    if (!ticket.ID) {
      return;
    }
    if (!this.isLoggedIn) {
      this.openInfo('กรุณาเข้าสู่ระบบเจ้าหน้าที่ก่อน');
      return;
    }
    this.ticketService.releaseTicket(ticket.ID).subscribe({
      next: (updatedTicket) => {
        const index = this.tickets.findIndex(t => t.ID === updatedTicket.ID);
        if (index !== -1) {
          this.tickets[index] = updatedTicket;
        }
      },
      error: (err) => {
        console.error('Error releasing ticket', err);
        this.openInfo('ไม่สามารถส่งคืนทิกเก็ตได้ กรุณาลองใหม่ หรือตรวจสอบการเชื่อมต่อเซิร์ฟเวอร์');
      }
    });
  }

  completeTicket(ticket: Ticket): void {
    if (!ticket.ID) {
      return;
    }
    if (!this.isLoggedIn) {
      this.openInfo('กรุณาเข้าสู่ระบบเจ้าหน้าที่ก่อน');
      return;
    }
    this.openConfirm('ยืนยันว่าคุณต้องการปิดงานทิกเก็ตนี้หรือไม่?', () => {
      this.ticketService.completeTicket(ticket.ID as number).subscribe({
        next: (updatedTicket) => {
          const index = this.tickets.findIndex(t => t.ID === updatedTicket.ID);
          if (index !== -1) {
            this.tickets[index] = updatedTicket;
          }
          this.ticketUpdated.emit(updatedTicket);
          this.openInfo(`ปิดงานทิกเก็ต #${ticket.ID} เรียบร้อยแล้ว`);
        },
        error: (err) => {
          console.error('Error completing ticket', err);
          this.openInfo('ไม่สามารถปิดงานทิกเก็ตได้ กรุณาลองใหม่ หรือตรวจสอบการเชื่อมต่อเซิร์ฟเวอร์');
        }
      });
    });
  }

  toggleReplies(ticket: Ticket): void {
    if (!ticket.ID) {
      return;
    }
    if (ticket.repliesLoaded) {
      ticket.showReplies = !ticket.showReplies;
      return;
    }

    this.ticketService.getReplies(ticket.ID).subscribe({
      next: (replies: TicketReply[]) => {
        ticket.replies = replies;
        ticket.repliesLoaded = true;
        ticket.showReplies = true;
      },
      error: (err) => {
        console.error('Error loading ticket replies', err);
        this.openInfo('ไม่สามารถโหลดประวัติทิกเก็ตได้ กรุณาลองใหม่ หรือตรวจสอบการเชื่อมต่อเซิร์ฟเวอร์');
      }
    });
  }

  submitReply(ticket: Ticket): void {
    if (!this.isLoggedIn) {
      this.openInfo('กรุณาเข้าสู่ระบบเจ้าหน้าที่ก่อน');
      return;
    }
    if (!ticket.ID) {
      return;
    }
    const message = (ticket.newReplyMessage || '').trim();
    if (!message) {
      this.openInfo('กรุณากรอกข้อความตอบกลับ');
      return;
    }
    this.ticketService.addReply(ticket.ID, message).subscribe({
      next: (reply: TicketReply) => {
        if (!ticket.replies) {
          ticket.replies = [];
        }
        ticket.replies.push(reply);
        ticket.newReplyMessage = '';
        ticket.showReplies = true;
      },
      error: (err) => {
        console.error('Error adding reply', err);
        this.openInfo('ไม่สามารถส่งข้อความตอบกลับได้ กรุณาลองใหม่ หรือตรวจสอบการเชื่อมต่อเซิร์ฟเวอร์');
      }
    });
  }
}
