import { Component, EventEmitter, HostListener, Input, OnInit, Output } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { TicketService, Ticket, TicketReply, AgentUser, ActivityLog } from '../../services/ticket.service';

type AgentSummary = {
  name: string;
  assignedCount: number;
  workingCount: number;
  completedCount: number;
  deletedCount: number;
  completionPercent: number;
  statusLabel: string;
};

type ActionBars = {
  create: number;
  assign: number;
  progress: number;
  complete: number;
  delete: number;
};

type TicketColumnView = 'all' | 'recent';

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
  logs: ActivityLog[] = [];

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
  private recentExpandedTicketIds = new Set<number>();

  activeCategory: 'all' | 'open' | 'in_progress' | 'closed' | 'unassigned' = 'all';
  analyticsFromDate = '';
  analyticsToDate = '';

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
    this.initializeDateRange();
    if (this.isLoggedIn) {
      this.loadLogs();
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

  private initializeDateRange(): void {
    const end = new Date();
    const start = new Date();
    start.setDate(end.getDate() - 6);
    this.analyticsFromDate = this.toDateInputValue(start);
    this.analyticsToDate = this.toDateInputValue(end);
  }

  private toDateInputValue(date: Date): string {
    const year = date.getFullYear();
    const month = `${date.getMonth() + 1}`.padStart(2, '0');
    const day = `${date.getDate()}`.padStart(2, '0');
    return `${year}-${month}-${day}`;
  }

  loadLogs(): void {
    if (!this.isLoggedIn) {
      this.logs = [];
      return;
    }
    this.ticketService.getLogs().subscribe({
      next: (logs) => {
        this.logs = logs;
      },
      error: (err) => {
        console.error('Failed to load logs', err);
      }
    });
  }

  onDateRangeChanged(): void {
    if (!this.analyticsFromDate || !this.analyticsToDate) {
      return;
    }
    if (this.analyticsFromDate > this.analyticsToDate) {
      const swap = this.analyticsFromDate;
      this.analyticsFromDate = this.analyticsToDate;
      this.analyticsToDate = swap;
    }
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

  private isAgentLogRole(role?: string): boolean {
    if (!role) {
      return false;
    }
    const normalized = role.toLowerCase();
    return normalized === 'admin'
      || normalized === 'agent'
      || normalized === 'staff'
      || normalized.includes('admin')
      || normalized.includes('agent')
      || normalized.includes('staff');
  }

  getAgentTickets(): Ticket[] {
    if (!this.currentAgentName) {
      return [];
    }
    return this.sortTicketsNewestFirst(
      this.tickets.filter(t => t.assigned_to === this.currentAgentName)
    );
  }

  getRecentRepliedTickets(): Ticket[] {
    const latestByTicketId = new Map<number, number>();
    this.logs.forEach(log => {
      if (log.action !== 'CREATE_TICKET' && log.action !== 'REPLY_TICKET') {
        return;
      }
      if (log.action === 'REPLY_TICKET' && this.isAgentLogRole(log.role)) {
        return;
      }
      const ticketId = this.extractTicketId(log.details);
      if (!ticketId) {
        return;
      }
      const ts = this.parseLogTimestamp(log.CreatedAt);
      if (ts === null) {
        return;
      }
      const prev = latestByTicketId.get(ticketId);
      if (prev === undefined || ts > prev) {
        latestByTicketId.set(ticketId, ts);
      }
    });

    const ticketsById = new Map<number, Ticket>();
    this.tickets.forEach(ticket => {
      if (ticket.ID) {
        ticketsById.set(ticket.ID, ticket);
      }
    });

    return Array.from(latestByTicketId.entries())
      .map(([ticketId, ts]) => ({ ticket: ticketsById.get(ticketId), ts }))
      .filter(item => !!item.ticket)
      .sort((a, b) => b.ts - a.ts)
      .map(item => item.ticket as Ticket)
      .slice(0, 10);
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

  getFilteredLogsByDateRange(): ActivityLog[] {
    const fromTs = this.getStartTimestamp(this.analyticsFromDate);
    const toTs = this.getEndTimestamp(this.analyticsToDate);
    if (fromTs === null || toTs === null) {
      return this.logs;
    }
    return this.logs.filter(log => {
      const logTs = this.parseLogTimestamp(log.CreatedAt);
      return logTs !== null && logTs >= fromTs && logTs <= toTs;
    });
  }

  getActionBarsByDay(): Array<{ dateLabel: string; bars: ActionBars }> {
    const fromTs = this.getStartTimestamp(this.analyticsFromDate);
    const toTs = this.getEndTimestamp(this.analyticsToDate);
    if (fromTs === null || toTs === null || fromTs > toTs) {
      return [];
    }

    const days: Array<{ key: string; dateLabel: string; bars: ActionBars }> = [];
    const current = new Date(fromTs);
    while (current.getTime() <= toTs) {
      const key = this.toDateInputValue(current);
      const dateLabel = `${current.getDate()}/${current.getMonth() + 1}`;
      days.push({
        key,
        dateLabel,
        bars: {
          create: 0,
          assign: 0,
          progress: 0,
          complete: 0,
          delete: 0
        }
      });
      current.setDate(current.getDate() + 1);
    }

    const byKey = new Map<string, ActionBars>();
    days.forEach(day => byKey.set(day.key, day.bars));

    this.getFilteredLogsByDateRange().forEach(log => {
      const ts = this.parseLogTimestamp(log.CreatedAt);
      if (ts === null) {
        return;
      }
      const key = this.toDateInputValue(new Date(ts));
      const target = byKey.get(key);
      if (!target) {
        return;
      }
      if (log.action === 'CREATE_TICKET') {
        target.create += 1;
      } else if (log.action === 'ASSIGN_TICKET') {
        target.assign += 1;
      } else if (log.action === 'REPLY_TICKET') {
        target.progress += 1;
      } else if (log.action === 'COMPLETE_TICKET') {
        target.complete += 1;
      } else if (log.action === 'DELETE_TICKET') {
        target.delete += 1;
      }
    });

    return days.map(day => ({ dateLabel: day.dateLabel, bars: day.bars }));
  }

  getMaxGraphValue(rows: Array<{ dateLabel: string; bars: ActionBars }>): number {
    const max = rows.reduce((currentMax, row) => {
      const values = [row.bars.create, row.bars.assign, row.bars.progress, row.bars.complete, row.bars.delete];
      return Math.max(currentMax, ...values);
    }, 0);
    return max > 0 ? max : 1;
  }

  getLinePath(rows: Array<{ dateLabel: string; bars: ActionBars }>, action: keyof ActionBars): string {
    if (!rows.length) {
      return '';
    }
    const max = this.getMaxGraphValue(rows);
    return rows
      .map((row, index) => {
        const x = this.getLinePointX(index, rows.length);
        const y = this.getLinePointY(row.bars[action], max);
        return `${index === 0 ? 'M' : 'L'} ${x} ${y}`;
      })
      .join(' ');
  }

  getLineDots(rows: Array<{ dateLabel: string; bars: ActionBars }>, action: keyof ActionBars): Array<{ x: number; y: number; value: number; dateLabel: string }> {
    const max = this.getMaxGraphValue(rows);
    return rows.map((row, index) => ({
      x: this.getLinePointX(index, rows.length),
      y: this.getLinePointY(row.bars[action], max),
      value: row.bars[action],
      dateLabel: row.dateLabel
    }));
  }

  getChartColumns(rows: Array<{ dateLabel: string; bars: ActionBars }>): string {
    if (rows.length <= 0) {
      return '1fr';
    }
    if (rows.length <= 12) {
      return `repeat(${rows.length}, minmax(0, 1fr))`;
    }
    return `repeat(${rows.length}, 44px)`;
  }

  getBarHeight(value: number, max: number): string {
    if (value <= 0 || max <= 0) {
      return '0%';
    }
    const ratio = value / max;
    return `${Math.max(2, Math.round(ratio * 100))}%`;
  }

  getCompareGraphMax(rows: Array<{ dateLabel: string; bars: ActionBars }>): number {
    const max = rows.reduce((currentMax, row) => {
      return Math.max(currentMax, row.bars.create, row.bars.progress, row.bars.complete, row.bars.delete);
    }, 0);
    return max > 0 ? max : 1;
  }

  getYAxisTicks(rows: Array<{ dateLabel: string; bars: ActionBars }>): Array<{ label: string; percent: number }> {
    const max = this.getCompareGraphMax(rows);
    if (max <= 4) {
      return Array.from({ length: max + 1 }, (_, value) => ({
        label: this.formatChartNumber(value),
        percent: max > 0 ? (value / max) * 100 : 0
      }));
    }

    const steps = 4;
    const values = Array.from({ length: steps + 1 }, (_, index) => {
      if (index === 0) {
        return 0;
      }
      if (index === steps) {
        return max;
      }
      return Math.round((max * index) / steps);
    });

    for (let i = 1; i < values.length; i += 1) {
      if (values[i] <= values[i - 1]) {
        values[i] = values[i - 1] + 1;
      }
    }
    values[values.length - 1] = max;

    return values.map((value, index) => ({
      label: this.formatChartNumber(value),
      percent: (index / steps) * 100
    }));
  }

  getLineGuideRows(): number[] {
    return [0, 25, 50, 75, 100];
  }

  formatChartNumber(value: number): string {
    return new Intl.NumberFormat('th-TH').format(value);
  }

  private getLinePointX(index: number, total: number): number {
    if (total <= 1) {
      return 50;
    }
    return Number(((index / (total - 1)) * 100).toFixed(2));
  }

  private getLinePointY(value: number, max: number): number {
    if (max <= 0) {
      return 100;
    }
    const ratio = value / max;
    return Number((100 - ratio * 100).toFixed(2));
  }

  getActionCount(action: string): number {
    return this.getFilteredLogsByDateRange().filter(log => log.action === action).length;
  }

  getAgentSummaries(): AgentSummary[] {
    const summaries = new Map<string, AgentSummary>();
    const ensure = (name: string): AgentSummary => {
      const normalized = name.trim();
      const existing = summaries.get(normalized);
      if (existing) {
        return existing;
      }
      const created: AgentSummary = {
        name: normalized,
        assignedCount: 0,
        workingCount: 0,
        completedCount: 0,
        deletedCount: 0,
        completionPercent: 0,
        statusLabel: 'ยังไม่รับงาน'
      };
      summaries.set(normalized, created);
      return created;
    };

    this.getFilteredLogsByDateRange().forEach(log => {
      const actorName = (log.user_name || '').trim();
      if (!actorName) {
        return;
      }
      if (log.action === 'ASSIGN_TICKET') {
        ensure(actorName).assignedCount += 1;
      } else if (log.action === 'COMPLETE_TICKET') {
        ensure(actorName).completedCount += 1;
      } else if (log.action === 'DELETE_TICKET') {
        ensure(actorName).deletedCount += 1;
      }
    });

    this.tickets.forEach(ticket => {
      const assignee = (ticket.assigned_to || '').trim();
      if (!assignee) {
        return;
      }
      const status = (ticket.status || '').toLowerCase();
      if (status !== 'closed') {
        ensure(assignee).workingCount += 1;
      }
    });

    return Array.from(summaries.values())
      .map(summary => {
        const base = summary.completedCount + summary.workingCount;
        summary.completionPercent = base > 0 ? Math.round((summary.completedCount / base) * 100) : 0;
        summary.statusLabel = summary.workingCount > 0
          ? 'ดำเนินงานอยู่'
          : summary.completedCount > 0
            ? 'เสร็จสิ้น'
            : summary.assignedCount > 0
              ? 'รับงานแล้ว'
              : 'ยังไม่รับงาน';
        return summary;
      })
      .sort((a, b) => {
        const aScore = a.workingCount + a.completedCount + a.assignedCount;
        const bScore = b.workingCount + b.completedCount + b.assignedCount;
        return bScore - aScore;
      });
  }

  getPercentBarWidth(percent: number): string {
    const safe = Number.isFinite(percent) ? Math.max(0, Math.min(100, percent)) : 0;
    return `${safe}%`;
  }

  private parseLogTimestamp(value?: string): number | null {
    if (!value) {
      return null;
    }
    const ts = Date.parse(value);
    return Number.isNaN(ts) ? null : ts;
  }

  private getStartTimestamp(dateValue: string): number | null {
    if (!dateValue) {
      return null;
    }
    const ts = Date.parse(`${dateValue}T00:00:00`);
    return Number.isNaN(ts) ? null : ts;
  }

  private getEndTimestamp(dateValue: string): number | null {
    if (!dateValue) {
      return null;
    }
    const ts = Date.parse(`${dateValue}T23:59:59.999`);
    return Number.isNaN(ts) ? null : ts;
  }

  private extractTicketId(details?: string): number | null {
    if (!details) {
      return null;
    }
    const match = details.match(/#(\d+)/);
    if (!match) {
      return null;
    }
    const id = Number(match[1]);
    return Number.isFinite(id) ? id : null;
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
        this.loadLogs();
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
    this.logs = [];
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
          this.loadLogs();
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
          this.loadLogs();
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
        this.loadLogs();
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
        this.loadLogs();
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
    this.activeCategory = 'all';
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
        this.loadLogs();
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
          this.loadLogs();
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

  isRepliesVisible(ticket: Ticket, view: TicketColumnView = 'all'): boolean {
    if (!ticket.ID) {
      return false;
    }
    if (view === 'recent') {
      return false;
    }
    return !!ticket.showReplies;
  }

  toggleReplies(ticket: Ticket, view: TicketColumnView = 'all'): void {
    if (!ticket.ID) {
      return;
    }
    if (view === 'recent') {
      this.openRecentInMain(ticket);
      return;
    }
    if (ticket.repliesLoaded) {
      const shouldOpen = !ticket.showReplies;
      this.closeAllReplies();
      ticket.showReplies = shouldOpen;
      if (ticket.showReplies) {
        this.focusReplyInput(ticket.ID);
      }
      return;
    }
    this.closeAllReplies();
    this.ensureRepliesVisible(ticket, false, true, () => {
      ticket.showReplies = !ticket.showReplies;
      if (ticket.showReplies && ticket.ID) {
        this.focusReplyInput(ticket.ID);
      }
    });
  }

  openRecentInMain(ticket: Ticket): void {
    if (!ticket.ID) {
      return;
    }
    const ticketId = ticket.ID;
    this.closeDetail();
    this.activeCategory = 'all';
    this.filterHasAttachment = false;
    const target = this.tickets.find(t => t.ID === ticket.ID) || ticket;
    this.closeAllReplies();
    if (target.repliesLoaded) {
      target.showReplies = true;
      this.scrollToTicket(ticketId);
      return;
    }
    this.ensureRepliesVisible(target, false, true, () => {
      this.scrollToTicket(ticketId);
    });
  }

  submitReply(ticket: Ticket, view: TicketColumnView = 'all'): void {
    if (!this.isLoggedIn) {
      this.openInfo('กรุณาเข้าสู่ระบบเจ้าหน้าที่ก่อน');
      return;
    }
    if (!ticket.ID) {
      return;
    }
    const message = (ticket.newReplyMessage || '').trim();
    const attachment = ticket.newReplyAttachment || null;
    if (!message && !attachment) {
      this.openInfo('กรุณากรอกข้อความตอบกลับ หรือแนบรูปภาพ');
      return;
    }
    this.ticketService.addReplyWithAttachment(ticket.ID, message, attachment).subscribe({
      next: (reply: TicketReply) => {
        if (!ticket.replies) {
          ticket.replies = [];
        }
        ticket.replies.push(reply);
        ticket.newReplyMessage = '';
        ticket.newReplyAttachment = null;
        if (view === 'recent') {
          this.activeCategory = 'all';
        }
        this.closeAllReplies();
        ticket.showReplies = true;
        if (ticket.ID) {
          this.focusReplyInput(ticket.ID);
        }
        this.loadLogs();
      },
      error: (err) => {
        console.error('Error adding reply', err);
        this.openInfo('ไม่สามารถส่งข้อความตอบกลับได้ กรุณาลองใหม่ หรือตรวจสอบการเชื่อมต่อเซิร์ฟเวอร์');
      }
    });
  }

  onReplyAttachmentSelected(event: Event, ticket: Ticket): void {
    const input = event.target as HTMLInputElement;
    if (!input.files || input.files.length === 0) {
      ticket.newReplyAttachment = null;
      return;
    }
    ticket.newReplyAttachment = input.files[0];
  }

  clearReplyAttachment(ticket: Ticket): void {
    ticket.newReplyAttachment = null;
  }

  onReplyKeydown(event: KeyboardEvent, ticket: Ticket, view: TicketColumnView = 'all'): void {
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
      event.preventDefault();
      this.submitReply(ticket, view);
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
      newReplyMessage: existing.newReplyMessage,
      newReplyAttachment: existing.newReplyAttachment
    };
  }

  private ensureRepliesVisible(
    ticket: Ticket,
    focusReplyAfterLoaded: boolean,
    showInAllColumn = true,
    onVisible?: () => void
  ): void {
    if (!ticket.ID) {
      return;
    }
    if (ticket.repliesLoaded) {
      if (showInAllColumn) {
        ticket.showReplies = true;
      }
      if (onVisible) {
        onVisible();
      }
      if (focusReplyAfterLoaded) {
        this.focusReplyInput(ticket.ID);
      }
      return;
    }
    this.ticketService.getReplies(ticket.ID).subscribe({
      next: (replies: TicketReply[]) => {
        ticket.replies = replies;
        ticket.repliesLoaded = true;
        if (showInAllColumn) {
          ticket.showReplies = true;
        }
        if (onVisible) {
          onVisible();
        }
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

  private closeAllReplies(): void {
    this.tickets.forEach(item => {
      item.showReplies = false;
    });
    this.recentExpandedTicketIds.clear();
  }

  private scrollToTicket(ticketId: number): void {
    setTimeout(() => {
      const element = document.querySelector<HTMLElement>(`.ticket-main-layout [data-ticket-id="${ticketId}"]`);
      element?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 0);
  }

  private focusReplyInput(ticketId: number): void {
    setTimeout(() => {
      const element = document.querySelector<HTMLTextAreaElement>(`textarea[data-reply-input-id="${ticketId}"]`);
      element?.focus();
    }, 0);
  }
}
