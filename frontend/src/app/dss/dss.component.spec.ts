import { ComponentFixture, TestBed } from '@angular/core/testing';

import { DssComponent } from './dss.component';

describe('DssComponent', () => {
  let component: DssComponent;
  let fixture: ComponentFixture<DssComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ DssComponent ]
    })
    .compileComponents();
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(DssComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
