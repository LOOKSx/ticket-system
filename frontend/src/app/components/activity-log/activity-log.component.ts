import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { TicketService, ActivityLog } from '../../services/ticket.service';

@Component({
  selector: 'app-activity-log',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './activity-log.component.html',
  styleUrls: ['./activity-log.component.css']
})
export class ActivityLogComponent implements OnInit {
  logs: ActivityLog[] = [];
  loading = true;

  constructor(private ticketService: TicketService) {}

  ngOnInit(): void {
    this.loadLogs();
  }

  getThaiRole(role: string): string {
    switch (role) {
      case 'Admin': return 'เจ้าหน้าที่';
      case 'customer': return 'ลูกค้า';
      default: return role;
    }
  }

  getThaiAction(action: string): string {
    const actionMap: { [key: string]: string } = {
      'LOGIN': 'เข้าสู่ระบบ',
      'LOGOUT': 'ออกจากระบบ',
      'CREATE_TICKET': 'สร้างทิกเก็ต',
      'REPLY_TICKET': 'ตอบกลับทิกเก็ต',
      'ASSIGN_TICKET': 'รับเคส',
      'RELEASE_TICKET': 'ส่งคืนเคส',
      'COMPLETE_TICKET': 'ปิดงาน',
      'DELETE_TICKET': 'ลบทิกเก็ต',
      'REGISTER': 'ลงทะเบียน'
    };
    return actionMap[action] || action;
  }

  loadLogs(): void {
    this.ticketService.getLogs().subscribe({
      next: (data) => {
        this.logs = data;
        this.loading = false;
      },
      error: (err) => {
        console.error('Failed to load logs', err);
        this.loading = false;
      }
    });
  }
}
