import matplotlib
import matplotlib.pyplot as plt
matplotlib.use('Agg')
import io
import numpy as np
def create_accuracy_chart(algorithms, train_accuracy,test_accuracy ):
    plt.figure(figsize=(10, 6))
    x = range(len(algorithms))
    width = 0.35

    plt.bar([i - width/2 for i in x], train_accuracy, width, label='Train Accuracy', color='purple')
    plt.bar([i + width/2 for i in x], test_accuracy, width, label='Test Accuracy', color='green')

    plt.xlabel('Algorithms')
    plt.ylabel('Accuracy')
    plt.title('Accuracy Comparison')
    plt.xticks(x, algorithms, rotation=45)
    plt.legend()
    plt.tight_layout()

    img = io.BytesIO()
    plt.savefig(img, format='png')
    img.seek(0)
    return img

def create_metric_chart(metric_data, metric_name,classes):
    plt.figure(figsize=(12, 6))
    x = np.arange(len(classes))
    width = 0.25
    
    for i, (algo, values) in enumerate(metric_data.items()):
        plt.bar(x + i*width, values, width, label=algo)
    
    plt.xlabel('Class')
    plt.ylabel(metric_name)
    plt.title(f'{metric_name} Comparison by Class and Algorithm')
    plt.xticks(x + width, classes, rotation=45, ha='right')
    plt.legend(loc='upper center', bbox_to_anchor=(0.5, -0.15), ncol=3)
    plt.tight_layout()

    img = io.BytesIO()
    plt.savefig(img, format='png')
    img.seek(0)
    return img

def create_support_chart(classes, support_data):
    plt.figure(figsize=(10, 6))
    plt.bar(classes, support_data, color='lightblue')
    plt.xlabel('Class')
    plt.ylabel('Support')
    plt.title('Support Distribution Across Classes')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()

    img = io.BytesIO()
    plt.savefig(img, format='png')
    img.seek(0)
    return img
