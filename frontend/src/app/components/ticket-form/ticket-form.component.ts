import { Component, EventEmitter, Output } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { TicketService, Ticket } from '../../services/ticket.service';

@Component({
  selector: 'app-ticket-form',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './ticket-form.component.html',
  styleUrls: ['./ticket-form.component.css']
})
export class TicketFormComponent {
  @Output() ticketCreated = new EventEmitter<Ticket>();
  @Output() formError = new EventEmitter<string>();

  newTicket: Ticket = {
    title: '',
    description: '',
    priority: 'medium',
    phone_number: ''
  };

  selectedFile: File | null = null;

  constructor(private ticketService: TicketService) {}

  onFileSelected(event: Event): void {
    const input = event.target as HTMLInputElement;
    if (input.files && input.files.length > 0) {
      this.selectedFile = input.files[0];
    } else {
      this.selectedFile = null;
    }
  }

  onSubmit(): void {
    if (!this.isCustomerLoggedIn()) {
      this.formError.emit('กรุณาเข้าสู่ระบบหรือลงทะเบียนลูกค้าก่อนส่งทิกเก็ต');
      return;
    }

    const title = (this.newTicket.title || '').trim();
    const description = (this.newTicket.description || '').trim();
    const phone = (this.newTicket.phone_number || '').trim();

    if (!title || !description || !phone) {
      this.formError.emit('กรุณากรอกข้อมูลให้ครบ รวมถึงเบอร์มือถือ');
      return;
    }

    if (!this.isValidThaiPhone(phone)) {
      this.formError.emit('กรุณากรอกเบอร์มือถือให้ถูกต้อง (ต้องเป็นตัวเลข 9–11 หลักขึ้นต้นด้วย 0)');
      return;
    }

    const formData = new FormData();
    formData.append('title', title);
    formData.append('description', description);
    formData.append('priority', this.newTicket.priority);
    formData.append('phone', phone);

    if (this.selectedFile) {
      formData.append('attachment', this.selectedFile);
    }

    this.ticketService.createTicket(formData).subscribe({
      next: (createdTicket) => {
        this.ticketCreated.emit(createdTicket);
        this.newTicket = { title: '', description: '', priority: 'medium', phone_number: '' };
        this.selectedFile = null;
      },
      error: (err) => {
        console.error('Error creating ticket', err);
        this.formError.emit('ไม่สามารถสร้างทิกเก็ตได้ กรุณาลองใหม่');
      }
    });
  }

  isValidThaiPhone(phone: string): boolean {
    const cleaned = phone.replace(/[^0-9]/g, '');
    return /^0\d{8,10}$/.test(cleaned);
  }

  private isCustomerLoggedIn(): boolean {
    return !!localStorage.getItem('customerToken');
  }

  get customerLoggedIn(): boolean {
    return this.isCustomerLoggedIn();
  }
}
