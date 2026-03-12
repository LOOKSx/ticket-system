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

  department = '';
  service = '';

  readonly departmentOptions: string[] = [
    'IT',
    'บัญชี',
    'การเงิน',
    'บุคคล (HR)',
    'จัดซื้อ',
    'คลังสินค้า',
    'ขาย',
    'การตลาด',
    'บริหาร',
    'อื่นๆ'
  ];

  readonly serviceOptions: string[] = [
    'แจ้งปัญหาโปรแกรม/ระบบ',
    'ขอสิทธิ์เข้าใช้งาน',
    'รีเซ็ตรหัสผ่าน/บัญชีผู้ใช้',
    'อุปกรณ์คอมพิวเตอร์/ฮาร์ดแวร์',
    'อินเทอร์เน็ต/เครือข่าย',
    'เครื่องพิมพ์/สแกนเนอร์',
    'อีเมล',
    'อื่นๆ'
  ];

  selectedFiles: File[] = [];

  constructor(private ticketService: TicketService) {}

  onFileSelected(event: Event): void {
    const input = event.target as HTMLInputElement;
    const incoming = input.files ? Array.from(input.files) : [];
    if (incoming.length === 0) {
      this.selectedFiles = [];
      return;
    }
    const all = [...this.selectedFiles, ...incoming];
    if (all.length > 5) {
      this.selectedFiles = all.slice(0, 5);
      this.formError.emit('เลือกไฟล์ได้สูงสุด 5 ไฟล์ต่อทิกเก็ต');
    } else {
      this.selectedFiles = all;
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
    const department = (this.department || '').trim();
    const service = (this.service || '').trim();

    if (!title || !description || !phone) {
      this.formError.emit('กรุณากรอกข้อมูลให้ครบ รวมถึงเบอร์มือถือ');
      return;
    }
    if (!department || !service) {
      this.formError.emit('กรุณาเลือกหน่วยงานและงานบริการ');
      return;
    }

    if (!this.isValidThaiPhone(phone)) {
      this.formError.emit('กรุณากรอกเบอร์มือถือให้ถูกต้อง (ต้องเป็นตัวเลข 9–11 หลักขึ้นต้นด้วย 0)');
      return;
    }

    const formData = new FormData();
    formData.append('title', title);
    formData.append('department', department);
    formData.append('service', service);
    formData.append('description', `จากหน่วยงาน: ${department}\nงานบริการ: ${service}\n\n${description}`);
    formData.append('priority', this.newTicket.priority);
    formData.append('phone', phone);

    if (this.selectedFiles?.length) {
      // Append as attachments[] to supportหลายไฟล์ (สูงสุด 5 ตามฝั่งเซิร์ฟเวอร์)
      const files = this.selectedFiles.slice(0, 5);
      for (const f of files) {
        formData.append('attachments', f);
      }
    }

    this.ticketService.createTicket(formData).subscribe({
      next: (createdTicket) => {
        this.ticketCreated.emit(createdTicket);
        this.newTicket = { title: '', description: '', priority: 'medium', phone_number: '' };
        this.department = '';
        this.service = '';
        this.selectedFiles = [];
      },
      error: (err) => {
        console.error('Error creating ticket', err);
        this.formError.emit('ไม่สามารถสร้างทิกเก็ตได้ กรุณาลองใหม่');
      }
    });
  }

  getSelectedFileNames(): string {
    return (this.selectedFiles || []).map(f => f.name).join(', ');
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
