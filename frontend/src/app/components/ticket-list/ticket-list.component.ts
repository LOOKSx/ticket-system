import { Component, EventEmitter, HostListener, Input, OnInit, Output } from '@angular/core';
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

  previewImage: string | null = null;
  previewZoom = 1;
  previewImageLoading = false;
  previewImageError = false;

  filterHasAttachment = false;

  private attachmentImageState: Record<string, { loaded: boolean; error: boolean }> = {};
  private attachmentMeta: Record<string, { fileName: string; fileSizeLabel: string }> = {};
  private attachmentRenderPath: Record<string, string> = {};
  private attachmentRetryCount: Record<string, number> = {};
  private assigningTicketIds = new Set<number>();

  activeCategory: 'all' | 'open' | 'in_progress' | 'closed' | 'unassigned' = 'all';

  constructor(private ticketService: TicketService) {}

  isImage(path: string): boolean {
    if (!path) return false;
    const lower = path.toLowerCase();
    return lower.endsWith('.jpg') || 
           lower.endsWith('.jpeg') || 
           lower.endsWith('.png') || 
           lower.endsWith('.gif') || 
           lower.endsWith('.webp') || 
           lower.endsWith('.bmp') || 
           lower.endsWith('.svg') || 
           lower.endsWith('.ico') || 
           lower.endsWith('.tif') || 
           lower.endsWith('.tiff') || 
           lower.endsWith('.heic');
  }

  openImage(path: string): void {
    this.previewImage = path;
    this.previewZoom = 1;
    this.previewImageLoading = true;
    this.previewImageError = false;
    document.body.style.overflow = 'hidden';
  }

  closeImage(): void {
    this.previewImage = null;
    this.previewImageLoading = false;
    this.previewImageError = false;
    this.previewZoom = 1;
    document.body.style.overflow = '';
  }

  zoomIn(): void {
    this.previewZoom = Math.min(3, this.previewZoom + 0.25);
  }

  zoomOut(): void {
    this.previewZoom = Math.max(0.5, this.previewZoom - 0.25);
  }

  resetZoom(): void {
    this.previewZoom = 1;
  }

  downloadPreviewImage(): void {
    if (!this.previewImage) {
      return;
    }
    const link = document.createElement('a');
    link.href = this.previewImage;
    link.download = this.getAttachmentFileName(this.previewImage);
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    link.click();
  }

  onPreviewImageLoad(): void {
    this.previewImageLoading = false;
    this.previewImageError = false;
  }

  onPreviewImageError(): void {
    this.previewImageLoading = false;
    this.previewImageError = true;
  }

  @HostListener('document:keydown', ['$event'])
  handlePreviewKeydown(event: KeyboardEvent): void {
    if (!this.previewImage) {
      return;
    }
    if (event.key === 'Escape') {
      this.closeImage();
      return;
    }
    if (event.key === '+' || event.key === '=') {
      event.preventDefault();
      this.zoomIn();
      return;
    }
    if (event.key === '-') {
      event.preventDefault();
      this.zoomOut();
      return;
    }
    if (event.key === '0') {
      event.preventDefault();
      this.resetZoom();
    }
  }

  private ensureAttachmentState(path: string): void {
    if (!this.attachmentImageState[path]) {
      this.attachmentImageState[path] = { loaded: false, error: false };
    }
    if (!this.attachmentRenderPath[path]) {
      this.attachmentRenderPath[path] = this.resolveAttachmentUrl(path);
    }
    if (this.attachmentRetryCount[path] === undefined) {
      this.attachmentRetryCount[path] = 0;
    }
    if (!this.attachmentMeta[path]) {
      this.attachmentMeta[path] = {
        fileName: this.getAttachmentFileName(path),
        fileSizeLabel: 'กำลังโหลดขนาดไฟล์...'
      };
      this.loadAttachmentMeta(path, this.attachmentRenderPath[path]);
    }
  }

  onAttachmentLoad(path: string): void {
    this.ensureAttachmentState(path);
    this.attachmentImageState[path].loaded = true;
    this.attachmentImageState[path].error = false;
    this.attachmentRetryCount[path] = 0;
  }

  onAttachmentError(path: string): void {
    this.ensureAttachmentState(path);
    const currentRetry = this.attachmentRetryCount[path] || 0;
    if (currentRetry < 2) {
      const nextRetry = currentRetry + 1;
      this.attachmentRetryCount[path] = nextRetry;
      this.attachmentImageState[path].loaded = false;
      this.attachmentImageState[path].error = false;
      this.attachmentRenderPath[path] = this.buildRetryAttachmentUrl(path, nextRetry);
      return;
    }
    this.attachmentImageState[path].loaded = false;
    this.attachmentImageState[path].error = true;
    this.attachmentMeta[path] = {
      fileName: this.getAttachmentFileName(path),
      fileSizeLabel: 'ไม่ทราบขนาดไฟล์'
    };
  }

  getAttachmentDisplayPath(path?: string): string {
    if (!path) {
      return '';
    }
    this.ensureAttachmentState(path);
    return this.attachmentRenderPath[path];
  }

  isAttachmentLoading(path?: string): boolean {
    if (!path) {
      return false;
    }
    this.ensureAttachmentState(path);
    const state = this.attachmentImageState[path];
    return !state.loaded && !state.error;
  }

  hasAttachmentError(path?: string): boolean {
    if (!path) {
      return false;
    }
    this.ensureAttachmentState(path);
    return this.attachmentImageState[path].error;
  }

  getAttachmentFileName(path: string): string {
    const withoutQuery = path.split('?')[0];
    const parts = withoutQuery.split('/');
    const rawName = parts[parts.length - 1] || 'ไฟล์แนบ';
    try {
      return decodeURIComponent(rawName);
    } catch {
      return rawName;
    }
  }

  getAttachmentSizeLabel(path?: string): string {
    if (!path) {
      return '-';
    }
    this.ensureAttachmentState(path);
    return this.attachmentMeta[path]?.fileSizeLabel || 'ไม่ทราบขนาดไฟล์';
  }

  private async loadAttachmentMeta(path: string, requestPath: string): Promise<void> {
    try {
      const response = await fetch(requestPath, { method: 'HEAD' });
      const size = response.headers.get('content-length');
      const fileSizeLabel = size ? this.formatBytes(Number(size)) : 'ไม่ทราบขนาดไฟล์';
      this.attachmentMeta[path] = {
        fileName: this.getAttachmentFileName(path),
        fileSizeLabel
      };
    } catch {
      this.attachmentMeta[path] = {
        fileName: this.getAttachmentFileName(path),
        fileSizeLabel: 'ไม่ทราบขนาดไฟล์'
      };
    }
  }

  private formatBytes(bytes: number): string {
    if (!Number.isFinite(bytes) || bytes <= 0) {
      return 'ไม่ทราบขนาดไฟล์';
    }
    const units = ['B', 'KB', 'MB', 'GB'];
    let value = bytes;
    let unitIndex = 0;
    while (value >= 1024 && unitIndex < units.length - 1) {
      value /= 1024;
      unitIndex += 1;
    }
    const shown = value >= 10 || unitIndex === 0 ? value.toFixed(0) : value.toFixed(1);
    return `${shown} ${units[unitIndex]}`;
  }

  private resolveAttachmentUrl(path: string): string {
    if (/^https?:\/\//i.test(path)) {
      return path;
    }
    if (path.startsWith('/uploads/')) {
      return path;
    }
    return path;
  }

  private buildRetryAttachmentUrl(path: string, retryStep: number): string {
    const retryToken = `_r=${Date.now()}`;
    if (retryStep === 1) {
      const current = this.attachmentRenderPath[path] || this.resolveAttachmentUrl(path);
      const joiner = current.includes('?') ? '&' : '?';
      return `${current}${joiner}${retryToken}`;
    }
    if (path.startsWith('/uploads/')) {
      const host = window.location.hostname;
      const candidate = `${window.location.protocol}//${host}:8080${path}`;
      return `${candidate}?${retryToken}`;
    }
    const current = this.attachmentRenderPath[path] || this.resolveAttachmentUrl(path);
    const joiner = current.includes('?') ? '&' : '?';
    return `${current}${joiner}${retryToken}`;
  }

  copyTicketId(id?: number): void {
    if (!id) {
      return;
    }
    const text = `#${id}`;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(() => {
        this.openInfo(`คัดลอกเลขทิกเก็ต ${text} แล้ว`);
      }).catch(() => {
        this.openInfo('ไม่สามารถคัดลอกเลขทิกเก็ตได้');
      });
      return;
    }
    this.openInfo('ไม่สามารถคัดลอกเลขทิกเก็ตได้');
  }

  getLatestUpdateAt(ticket: Ticket): string | null {
    const createdAt = ticket.CreatedAt ? Date.parse(ticket.CreatedAt) : NaN;
    const replies = ticket.replies || [];
    const latestReplyAt = replies.reduce((latest, reply) => {
      if (!reply.CreatedAt) {
        return latest;
      }
      const ts = Date.parse(reply.CreatedAt);
      if (Number.isNaN(ts)) {
        return latest;
      }
      return Number.isNaN(latest) || ts > latest ? ts : latest;
    }, Number.NaN);
    const latest = [createdAt, latestReplyAt].filter(ts => !Number.isNaN(ts)).sort((a, b) => b - a)[0];
    if (latest === undefined) {
      return null;
    }
    return new Date(latest).toISOString();
  }

  private sortTicketsNewestFirst(list: Ticket[]): Ticket[] {
    return [...list].sort((a, b) => {
      const aTime = a.CreatedAt ? Date.parse(a.CreatedAt) : NaN;
      const bTime = b.CreatedAt ? Date.parse(b.CreatedAt) : NaN;

      if (!Number.isNaN(aTime) && !Number.isNaN(bTime)) {
        return bTime - aTime;
      }

      const aId = a.ID ?? 0;
      const bId = b.ID ?? 0;
      return bId - aId;
    });
  }

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
    return this.sortTicketsNewestFirst(
      this.tickets.filter(t => t.assigned_to === this.currentAgentName)
    );
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
    const sorted = this.sortTicketsNewestFirst(this.tickets);
    let filtered = sorted;
    switch (this.activeCategory) {
      case 'open':
        filtered = sorted.filter(t => (t.status || '').toLowerCase() === 'open');
        break;
      case 'in_progress':
        filtered = sorted.filter(t => (t.status || '').toLowerCase() === 'in_progress');
        break;
      case 'closed':
        filtered = sorted.filter(t => (t.status || '').toLowerCase() === 'closed');
        break;
      case 'unassigned':
        filtered = sorted.filter(t => !t.assigned_to);
        break;
      default:
        filtered = sorted;
        break;
    }
    if (this.filterHasAttachment) {
      filtered = filtered.filter(t => !!t.attachment_path);
    }
    return filtered;
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
    if (this.assigningTicketIds.has(ticket.ID)) {
      return;
    }
    if (!this.isLoggedIn) {
      this.openInfo('กรุณาเข้าสู่ระบบเจ้าหน้าที่ก่อน');
      return;
    }
    this.assigningTicketIds.add(ticket.ID);
    this.ticketService.assignTicket(ticket.ID).subscribe({
      next: (updatedTicket) => {
        const merged = this.mergeTicketWithUiState(updatedTicket);
        const index = this.tickets.findIndex(t => t.ID === merged.ID);
        if (index !== -1) {
          this.tickets[index] = merged;
        }
        merged.showReplies = true;
        this.ensureRepliesVisible(merged, true);
        this.openInfo(`รับเคส #${merged.ID} เรียบร้อยแล้ว`);
        this.assigningTicketIds.delete(ticket.ID as number);
      },
      error: (err) => {
        console.error('Error assigning ticket', err);
        if (err.error && err.error.error === 'insufficient_permissions') {
          this.openInfo('คุณไม่มีสิทธิ์รับทิกเก็ตนี้');
        } else {
          this.openInfo('ไม่สามารถรับทิกเก็ตได้ กรุณาลองใหม่ หรือตรวจสอบการเชื่อมต่อเซิร์ฟเวอร์');
        }
        this.assigningTicketIds.delete(ticket.ID as number);
      }
    });
  }

  isAssigning(ticket: Ticket): boolean {
    if (!ticket.ID) {
      return false;
    }
    return this.assigningTicketIds.has(ticket.ID);
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
        if (err.error && err.error.error === 'not_ticket_owner') {
          this.openInfo('คุณไม่ใช่เจ้าของเคสนี้ ไม่สามารถส่งคืนได้');
        } else {
          this.openInfo('ไม่สามารถส่งคืนทิกเก็ตได้ กรุณาลองใหม่ หรือตรวจสอบการเชื่อมต่อเซิร์ฟเวอร์');
        }
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
          if (err.error && err.error.error === 'no_agent_reply_yet') {
            this.openInfo('กรุณาตอบกลับลูกค้าอย่างน้อย 1 ครั้งก่อนปิดงาน');
          } else if (err.error && err.error.error === 'not_ticket_owner') {
            this.openInfo('คุณไม่ใช่เจ้าของเคสนี้ ไม่สามารถปิดงานได้');
          } else if (err.error && err.error.error === 'ticket_already_closed') {
            this.openInfo('ทิกเก็ตนี้ถูกปิดไปแล้ว');
          } else {
            this.openInfo('ไม่สามารถปิดงานทิกเก็ตได้ กรุณาลองใหม่ หรือตรวจสอบการเชื่อมต่อเซิร์ฟเวอร์');
          }
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
      if (ticket.showReplies) {
        this.focusReplyInput(ticket.ID);
      }
      return;
    }
    this.ensureRepliesVisible(ticket, false);
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
        if (ticket.ID) {
          this.focusReplyInput(ticket.ID);
        }
      },
      error: (err) => {
        console.error('Error adding reply', err);
        this.openInfo('ไม่สามารถส่งข้อความตอบกลับได้ กรุณาลองใหม่ หรือตรวจสอบการเชื่อมต่อเซิร์ฟเวอร์');
      }
    });
  }

  onReplyKeydown(event: KeyboardEvent, ticket: Ticket): void {
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
      event.preventDefault();
      this.submitReply(ticket);
    }
  }

  getReplyLength(ticket: Ticket): number {
    return (ticket.newReplyMessage || '').trim().length;
  }

  private mergeTicketWithUiState(updatedTicket: Ticket): Ticket {
    const existing = this.tickets.find(t => t.ID === updatedTicket.ID);
    if (!existing) {
      return updatedTicket;
    }
    return {
      ...updatedTicket,
      showReplies: existing.showReplies,
      repliesLoaded: existing.repliesLoaded,
      replies: existing.replies,
      newReplyMessage: existing.newReplyMessage
    };
  }

  private ensureRepliesVisible(ticket: Ticket, focusReplyAfterLoaded: boolean): void {
    if (!ticket.ID) {
      return;
    }
    if (ticket.repliesLoaded) {
      ticket.showReplies = true;
      if (focusReplyAfterLoaded) {
        this.focusReplyInput(ticket.ID);
      }
      return;
    }
    this.ticketService.getReplies(ticket.ID).subscribe({
      next: (replies: TicketReply[]) => {
        ticket.replies = replies;
        ticket.repliesLoaded = true;
        ticket.showReplies = true;
        if (focusReplyAfterLoaded) {
          this.focusReplyInput(ticket.ID as number);
        }
      },
      error: (err) => {
        console.error('Error loading ticket replies', err);
        this.openInfo('ไม่สามารถโหลดประวัติทิกเก็ตได้ กรุณาลองใหม่ หรือตรวจสอบการเชื่อมต่อเซิร์ฟเวอร์');
      }
    });
  }

  private focusReplyInput(ticketId: number): void {
    setTimeout(() => {
      const element = document.querySelector<HTMLTextAreaElement>(`textarea[data-reply-input-id="${ticketId}"]`);
      element?.focus();
    }, 0);
  }
}
