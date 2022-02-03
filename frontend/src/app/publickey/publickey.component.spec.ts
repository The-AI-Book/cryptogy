import { ComponentFixture, TestBed } from '@angular/core/testing';

import { PublickeyComponent } from './publickey.component';

describe('PublickeyComponent', () => {
  let component: PublickeyComponent;
  let fixture: ComponentFixture<PublickeyComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ PublickeyComponent ]
    })
    .compileComponents();
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(PublickeyComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
