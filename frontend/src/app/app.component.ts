import { Component, OnInit, ViewChild } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { TicketService, Ticket, TicketReply } from './services/ticket.service';
import { TicketFormComponent } from './components/ticket-form/ticket-form.component';
import { TicketListComponent } from './components/ticket-list/ticket-list.component';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, FormsModule, TicketFormComponent, TicketListComponent],
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css', './app-ticket-history.css']
})
export class AppComponent implements OnInit {
  tickets: Ticket[] = [];
  customerTickets: Ticket[] = [];

  customerIsLoggedIn = false;
  customerName = '';
  agentName = '';

  authRole: 'customer' | 'Admin' | null = null;

  showCustomerAuthPanel = false;
  customerLoginEmail = '';
  customerLoginPassword = '';

  customerRegisterName = '';
  customerRegisterEmail = '';
  customerRegisterPassword = '';

  customerAuthMessage = '';

  confirmVisible = false;
  confirmMessage = '';
  confirmShowCancel = true;
  private pendingConfirmAction: (() => void) | null = null;

  @ViewChild(TicketListComponent) ticketList?: TicketListComponent;

  constructor(private ticketService: TicketService) {}

  ngOnInit(): void {
    const name = localStorage.getItem('customerName');
    const token = localStorage.getItem('customerToken');
    if (name && token) {
      this.customerIsLoggedIn = true;
      this.customerName = name;
      this.authRole = 'customer';
    } else {
      const storedAgentName = localStorage.getItem('agentName');
      const agentToken = localStorage.getItem('agentToken');
      if (storedAgentName && agentToken) {
        this.agentName = storedAgentName;
        this.authRole = 'Admin';
      }
    }

    this.loadTickets();
    this.loadCustomerTickets();
  }

  loadTickets(): void {
    this.ticketService.getTickets().subscribe({
      next: (data) => {
        this.tickets = data;
      },
      error: () => {
        this.tickets = [];
      }
    });
  }

  onTicketCreated(ticket: Ticket): void {
    this.tickets.push(ticket);
    this.loadCustomerTickets();
  }

  loadCustomerTickets(): void {
    const token = localStorage.getItem('customerToken');
    if (!token) {
      this.customerTickets = [];
      return;
    }

    this.ticketService.getCustomerTickets().subscribe({
      next: (data) => {
        this.customerTickets = data;
      },
      error: () => {
        this.customerTickets = [];
      }
    });
  }

  toggleCustomerAuthPanel(): void {
    this.showCustomerAuthPanel = !this.showCustomerAuthPanel;
  }

  loginCustomer(): void {
    this.customerAuthMessage = '';
    const email = this.customerLoginEmail.trim();
    const password = this.customerLoginPassword.trim();
    if (!email || !password) {
      this.customerAuthMessage = 'กรุณากรอกอีเมลและรหัสผ่านสำหรับเข้าสู่ระบบ';
      return;
    }

    this.ticketService.loginCustomer(email, password).subscribe({
      next: (res) => {
        // Handle role with potential whitespace or case issues
        const role = (res.role || '').trim();
        if (role === 'Admin') {
          localStorage.setItem('agentToken', res.token);
          localStorage.setItem('agentName', res.name);
          this.agentName = res.name;
          this.authRole = 'Admin';
          this.customerAuthMessage = 'เข้าสู่ระบบเจ้าหน้าที่เรียบร้อยแล้ว';
          if (this.ticketList) {
            this.ticketList.refreshLoginFromStorage();
          }
          this.loadTickets();
        } else {
          localStorage.setItem('customerToken', res.token);
          localStorage.setItem('customerName', res.name);
          this.customerIsLoggedIn = true;
          this.customerName = res.name;
          this.authRole = 'customer';
          this.customerAuthMessage = 'เข้าสู่ระบบลูกค้าเรียบร้อยแล้ว';
          this.loadCustomerTickets();
        }
        this.customerLoginPassword = '';
        this.showCustomerAuthPanel = false;
      },
      error: () => {
        this.customerAuthMessage = 'อีเมลหรือรหัสผ่านไม่ถูกต้อง';
      }
    });
  }

  registerCustomer(): void {
    this.customerAuthMessage = '';
    const name = this.customerRegisterName.trim();
    const email = this.customerRegisterEmail.trim();
    const password = this.customerRegisterPassword.trim();

    if (!name || !email || !password) {
      this.customerAuthMessage = 'กรุณากรอกชื่อ อีเมล และรหัสผ่านให้ครบถ้วน';
      return;
    }

    this.ticketService.registerCustomer(name, email, password).subscribe({
      next: (res) => {
        localStorage.setItem('customerToken', res.token);
        localStorage.setItem('customerName', res.name);
        this.customerIsLoggedIn = true;
        this.customerName = res.name;
        this.authRole = 'customer';
        this.customerRegisterPassword = '';
        this.customerAuthMessage = 'ลงทะเบียนและเข้าสู่ระบบเรียบร้อยแล้ว';
        this.showCustomerAuthPanel = false;
        this.loadCustomerTickets();
      },
      error: (err) => {
        console.error('Error registering customer', err);
        if (err?.status === 400) {
          this.customerAuthMessage = 'อีเมลนี้ถูกใช้ลงทะเบียนแล้ว';
        } else {
          this.customerAuthMessage = 'ไม่สามารถลงทะเบียนได้ กรุณาลองใหม่';
        }
      }
    });
  }

  logoutCustomer(): void {
    this.customerIsLoggedIn = false;
    this.customerName = '';
    localStorage.removeItem('customerToken');
    localStorage.removeItem('customerName');
    this.customerAuthMessage = 'ออกจากระบบลูกค้าแล้ว';
    this.showCustomerAuthPanel = false;
    this.customerTickets = [];
    this.authRole = null;
    this.customerLoginEmail = '';
    this.customerLoginPassword = '';
  }

  logoutAgent(): void {
    localStorage.removeItem('agentToken');
    localStorage.removeItem('agentName');
    this.agentName = '';
    this.authRole = null;
    if (this.ticketList) {
      this.ticketList.refreshLoginFromStorage();
    }
  }

  deleteCustomerTicket(ticket: Ticket): void {
    if (!ticket.ID) {
      return;
    }

    this.openConfirm('คุณต้องการลบทิกเก็ตนี้หรือไม่? การลบไม่สามารถย้อนกลับได้', () => {
      this.ticketService.deleteCustomerTicket(ticket.ID as number).subscribe({
        next: () => {
          this.customerTickets = this.customerTickets.filter(t => t.ID !== ticket.ID);

          const agentToken = localStorage.getItem('agentToken');
          if (agentToken) {
            this.loadTickets();
          }
        },
        error: (err) => {
          console.error('Error deleting customer ticket', err);
          this.openAlert('ไม่สามารถลบทิกเก็ตได้ กรุณาลองใหม่');
        }
      });
    });
  }

  resetCustomerTickets(): void {
    if (!this.customerIsLoggedIn) {
      return;
    }
    this.loadCustomerTickets();
  }

  toggleCustomerReplies(ticket: Ticket): void {
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
        console.error('Error loading customer ticket replies', err);
        this.openAlert('ไม่สามารถโหลดประวัติทิกเก็ตได้ กรุณาลองใหม่');
      }
    });
  }

  submitCustomerReply(ticket: Ticket): void {
    if (!this.customerIsLoggedIn) {
      this.openAlert('กรุณาเข้าสู่ระบบลูกค้าก่อนตอบกลับ');
      return;
    }
    if (!ticket.ID) {
      return;
    }
    const message = (ticket.newReplyMessage || '').trim();
    if (!message) {
      this.openAlert('กรุณากรอกข้อความตอบกลับ');
      return;
    }

    this.ticketService.addCustomerReply(ticket.ID, message).subscribe({
      next: (reply: TicketReply) => {
        if (!ticket.replies) {
          ticket.replies = [];
        }
        ticket.replies.push(reply);
        ticket.newReplyMessage = '';
        ticket.status = 'open';

        const agentToken = localStorage.getItem('agentToken');
        if (agentToken) {
          this.loadTickets();
        }
      },
      error: (err) => {
        console.error('Error adding customer reply', err);
        this.openAlert('ไม่สามารถบันทึกการตอบกลับได้ กรุณาลองใหม่');
      }
    });
  }

  onAgentReset(): void {
    this.loadTickets();
  }

  onTicketUpdated(updated: Ticket): void {
    this.tickets = this.tickets.map(t => (t.ID === updated.ID ? updated : t));

    const hasCustomerTicket = this.customerTickets.some(t => t.ID === updated.ID);
    if (hasCustomerTicket) {
      this.customerTickets = this.customerTickets.map(t =>
        t.ID === updated.ID ? updated : t
      );
      this.openAlert(`ทิกเก็ต #${updated.ID} ของคุณถูกเสร็จสิ้นแล้ว`);
    }
  }

  openAlert(message: string): void {
    this.confirmMessage = message;
    this.confirmShowCancel = false;
    this.pendingConfirmAction = null;
    this.confirmVisible = true;
  }

  private openConfirm(message: string, action: () => void): void {
    this.confirmMessage = message;
    this.confirmShowCancel = true;
    this.pendingConfirmAction = action;
    this.confirmVisible = true;
  }

  getCustomerStatusLabel(status?: string): string {
    if (!status) {
      return 'ไม่ระบุ';
    }
    switch (status.toLowerCase()) {
      case 'open':
        return 'ใหม่';
      case 'in_progress':
        return 'กำลังดำเนินการ';
      case 'closed':
        return 'เสร็จสิ้น';
      default:
        return status;
    }
  }

  getCustomerPriorityLabel(priority?: string): string {
    if (!priority) {
      return 'ไม่ระบุ';
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
}
