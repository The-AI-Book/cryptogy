import { ComponentFixture, TestBed } from '@angular/core/testing';

import { GammaPentagonalComponent } from './gamma-pentagonal.component';

describe('GammaPentagonalComponent', () => {
  let component: GammaPentagonalComponent;
  let fixture: ComponentFixture<GammaPentagonalComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ GammaPentagonalComponent ]
    })
    .compileComponents();
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(GammaPentagonalComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
