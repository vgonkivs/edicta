package ibkr

import (
	"context"

	"github.com/vgonkivs/edicta/examples/dca-agent/ibkrorder"
)

// PlaceRequest is one order in the broker's wire form. Only RequestFromOrder
// builds it, from a decoded order and nothing else.
type PlaceRequest struct {
	ClientOrderID string
	Account       string
	ConID         uint64
	Side          string
	Quantity      string
	OrderType     string
	Price         string
	TIF           string
}

// Broker is the venue. Both calls must honour ctx.
type Broker interface {
	// Place sends the order and returns the broker's order id. An error
	// means the outcome is not known unless the broker says otherwise.
	Place(ctx context.Context, req PlaceRequest) (orderID string, err error)
	// LookupByClientOrderID reports whether an order with this client id
	// exists. found is false only when the lookup covered every place the
	// order could be.
	LookupByClientOrderID(ctx context.Context, clientOrderID string) (orderID string, found bool, err error)
}

// RequestFromOrder maps the fields of a decoded order one to one and adds the
// client order id. It fills no defaults and sends no symbol.
func RequestFromOrder(o *ibkrorder.Order, clientOrderID string) PlaceRequest {
	r := PlaceRequest{
		ClientOrderID: clientOrderID,
		Account:       o.Account,
		ConID:         o.ConID,
		Quantity:      ibkrorder.FormatQty(o.Qty),
	}
	switch o.Side {
	case ibkrorder.SideBuy:
		r.Side = "BUY"
	case ibkrorder.SideSell:
		r.Side = "SELL"
	}
	if o.OrderType == ibkrorder.TypeLimit {
		r.OrderType = "LMT"
	}
	if o.LimitPrice != nil {
		r.Price = ibkrorder.FormatPrice(*o.LimitPrice)
	}
	switch o.TIF {
	case ibkrorder.TIFDay:
		r.TIF = "DAY"
	case ibkrorder.TIFGTC:
		r.TIF = "GTC"
	case ibkrorder.TIFIOC:
		r.TIF = "IOC"
	}
	return r
}
