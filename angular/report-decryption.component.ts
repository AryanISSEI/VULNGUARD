import { Component, Input } from '@angular/core';
import { ReportDecryptionService } from './report-decryption.service';

@Component({
  selector: 'app-report-decryption',
  templateUrl: './report-decryption.component.html',
  styleUrls: ['./report-decryption.component.css']
})
export class ReportDecryptionComponent {
  @Input() filename: string = '';
  decryptedData: any = null;
  errorMessage: string | null = null;
  isLoading: boolean = false;

  constructor(private decryptionService: ReportDecryptionService) {}

  onViewDecryptedReport(): void {
    if (!this.filename) {
      this.errorMessage = 'No filename provided.';
      return;
    }

    this.isLoading = true;
    this.decryptedData = null;
    this.errorMessage = null;

    this.decryptionService.decryptReport(this.filename).subscribe({
      next: (data) => {
        this.decryptedData = data;
        this.isLoading = false;
      },
      error: (err) => {
        this.isLoading = false;
        if (err.error && err.error.detail) {
          this.errorMessage = err.error.detail;
        } else {
          this.errorMessage = `An error occurred: ${err.message || 'Server unreachable'}`;
        }
      }
    });
  }

  get jsonString(): string {
    return JSON.stringify(this.decryptedData, null, 2);
  }
}
