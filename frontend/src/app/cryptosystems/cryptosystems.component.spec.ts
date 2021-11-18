import { ComponentFixture, TestBed } from '@angular/core/testing';

import { CryptosystemsComponent } from './cryptosystems.component';

describe('CryptosystemsComponent', () => {
  let component: CryptosystemsComponent;
  let fixture: ComponentFixture<CryptosystemsComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ CryptosystemsComponent ]
    })
    .compileComponents();
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(CryptosystemsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
