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
