package legacy

import (
	"context"
	"encoding/json/jsontext"
	"errors"

	"github.com/bifrost0x/webssh/internal/files/smb"
	"github.com/bifrost0x/webssh/internal/store"
)

// AddSMB registers the step of the area "smb": the saved SMB share
// definitions (E22), which the M1 release keeps in place.
func AddSMB(r *Registry) error {
	r.Schemas(smb.Schema())
	return r.Add(GroupHosts, func() Step { return &smbSharesStep{} })
}

// smbSharesStep migrates E22 verbatim: every record of
// users/user_N/smb_shares.json in list order, an empty domain kept as
// empty, unknown non-secret members kept. A document Python refuses to
// read (_valid_document: a record with a secret member, a field that is
// not in its canonical form, more than 1000 records) stops the migration.
type smbSharesStep struct {
	users []smbUser
	flags []Flag
	read  int
}

type smbUser struct {
	id      int64
	records []jsontext.Value
}

func (*smbSharesStep) Entity() string { return "E22" }

func (*smbSharesStep) Version() int { return 1 }

func (*smbSharesStep) accountScoped() bool { return true }

func (s *smbSharesStep) Read(ctx context.Context, src *Source) error {
	rows, err := src.AccountRows(ctx)
	if err != nil {
		return err
	}
	for _, a := range rows {
		doc, found, err := userStore(src, a.ID, "smb_shares")
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		recs, err := doc.RawList("smb_shares")
		if err != nil {
			return &StepError{UserID: a.ID, Record: "smb_shares.json", Err: err}
		}
		for _, f := range documentFlags(doc) {
			s.flags = append(s.flags, Flag{UserID: a.ID, ID: "smb_shares.json", Reason: f})
		}
		s.users = append(s.users, smbUser{id: a.ID, records: recs})
		s.read += len(recs)
	}
	return nil
}

func (s *smbSharesStep) Write(ctx context.Context, tx *store.Tx, _ Sealer) error {
	for _, u := range s.users {
		if err := smb.ImportTx(ctx, tx, u.id, u.records); err != nil {
			return &StepError{UserID: u.id, Record: "smb_shares.json", Err: err}
		}
	}
	return nil
}

// Verify reads every definition back: the same records byte for byte, in
// the same order.
func (s *smbSharesStep) Verify(ctx context.Context, tx *store.Tx, _ Opener) error {
	for _, u := range s.users {
		got, err := smb.SharesTx(ctx, tx, u.id)
		if err != nil {
			return &StepError{UserID: u.id, Err: err}
		}
		if !sameRecords(got, u.records) {
			return &StepError{UserID: u.id, Record: "smb_shares.json", Err: errors.New("legacy: the stored SMB share definitions differ")}
		}
	}
	return nil
}

func (s *smbSharesStep) Report() StepReport {
	return StepReport{Entity: "E22", Version: 1, Read: s.read, Written: s.read, Flagged: s.flags,
		accountNote: "SMB share definitions taken over verbatim for %d accounts; passwords were never stored with them", accounts: len(s.users)}
}
