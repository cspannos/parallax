use std::collections::{HashMap, VecDeque};

use protocol_types::{Height, OrderId, OwnerId, Price, Qty, Side};

use crate::book::{crosses, Book, RestingOrder};

/// Sorted `Vec` of price levels (ascending) plus FIFO deques.
#[derive(Clone, Debug, Default)]
pub struct VecBook {
    orders: HashMap<OrderId, RestingOrder, crate::IdHashBuilder>,
    bids: Vec<(Price, VecDeque<OrderId>)>,
    asks: Vec<(Price, VecDeque<OrderId>)>,
}

impl VecBook {
    fn levels_mut(&mut self, side: Side) -> &mut Vec<(Price, VecDeque<OrderId>)> {
        match side {
            Side::Buy => &mut self.bids,
            Side::Sell => &mut self.asks,
        }
    }

    fn find_level(levels: &[(Price, VecDeque<OrderId>)], price: Price) -> Result<usize, usize> {
        levels.binary_search_by(|(p, _)| p.cmp(&price))
    }

    fn unlink(&mut self, order: &RestingOrder) {
        let levels = self.levels_mut(order.side);
        if let Ok(i) = Self::find_level(levels, order.price) {
            if let Some(j) = levels[i].1.iter().position(|id| *id == order.id) {
                levels[i].1.remove(j);
            }
            if levels[i].1.is_empty() {
                levels.remove(i);
            }
        }
    }
}

impl Book for VecBook {
    fn insert(&mut self, order: RestingOrder) {
        let price = order.price;
        let id = order.id;
        let levels = self.levels_mut(order.side);
        match Self::find_level(levels, price) {
            Ok(i) => levels[i].1.push_back(id),
            Err(i) => levels.insert(i, (price, VecDeque::from([id]))),
        }
        self.orders.insert(id, order);
    }

    fn remove(&mut self, id: OrderId) -> Option<RestingOrder> {
        let order = self.orders.remove(&id)?;
        self.unlink(&order);
        Some(order)
    }

    fn get(&self, id: OrderId) -> Option<&RestingOrder> {
        self.orders.get(&id)
    }

    fn fill(&mut self, id: OrderId, qty: Qty) -> Option<RestingOrder> {
        let remaining = self.orders.get(&id)?.remaining.checked_sub(qty)?;
        if remaining.is_zero() {
            self.remove(id)
        } else {
            self.orders.get_mut(&id)?.remaining = remaining;
            self.orders.get(&id).cloned()
        }
    }

    fn best_cross(&self, taker: Side, limit: Price, skip_owner: OwnerId) -> Option<OrderId> {
        match taker {
            Side::Buy => {
                for (price, dq) in &self.asks {
                    if !crosses(taker, limit, *price) {
                        break;
                    }
                    for id in dq {
                        if let Some(o) = self.orders.get(id) {
                            if o.owner != skip_owner {
                                return Some(*id);
                            }
                        }
                    }
                }
                None
            }
            Side::Sell => {
                for (price, dq) in self.bids.iter().rev() {
                    if !crosses(taker, limit, *price) {
                        break;
                    }
                    for id in dq {
                        if let Some(o) = self.orders.get(id) {
                            if o.owner != skip_owner {
                                return Some(*id);
                            }
                        }
                    }
                }
                None
            }
        }
    }

    fn visit_canonical(&self, visit: &mut dyn FnMut(&RestingOrder)) {
        for (_, dq) in self.bids.iter().rev() {
            for id in dq {
                if let Some(o) = self.orders.get(id) {
                    visit(o);
                }
            }
        }
        for (_, dq) in &self.asks {
            for id in dq {
                if let Some(o) = self.orders.get(id) {
                    visit(o);
                }
            }
        }
    }

    fn collect_expired(&self, height: Height) -> Vec<OrderId> {
        let mut ids: Vec<OrderId> = self
            .orders
            .values()
            .filter(|o| o.expiry < height)
            .map(|o| o.id)
            .collect();
        ids.sort();
        ids
    }

    fn len(&self) -> usize {
        self.orders.len()
    }
}
