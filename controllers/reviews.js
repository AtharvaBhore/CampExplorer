const Campground = require('../models/campground');
const Review = require('../models/review');

module.exports.createReview = async (req, res) => {
    const { id } = req.params;
    const campground = await Campground.findById(id);
    const review = new Review(req.body.review);
    review.author = req.user._id;
    campground.reviews.push(review);
    await review.save();
    await campground.save();
    req.flash(`success`, 'Successfully added a review');
    res.redirect(`/campgrounds/${campground._id}`)
}

module.exports.deleteReview = async (req, res) => {
    const campground = await Campground.findByIdAndUpdate(req.params.id, { $pull: { reviews: req.params.reviewId } });
    const review = await Review.findByIdAndDelete(req.params.reviewId);
    req.flash(`success`, 'Successfully deleted a review');
    res.redirect(`/campgrounds/${campground._id}`)
}